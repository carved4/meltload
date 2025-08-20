package pe

import (
    "encoding/binary"
    "fmt"
    "log"
    "strings"
    "unsafe"

	api "github.com/carved4/go-wincall"
)

// hostCandidateDLLs is used when resolving API-set contracts and other indirect imports.
var hostCandidateDLLs = []string{
	"ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcrt.dll",
	"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll",
}

// RemoteImage encapsulates state needed to map a PE image into a remote process.
type RemoteImage struct {
	pHandle       uintptr
	pid           uint32
	bytes         []byte
	dllPtr        uintptr
	e_lfanew      uint32
	nt            *IMAGE_NT_HEADERS64
	preferredBase uintptr
	imageSize     uintptr
	base          uintptr
}

func newRemoteImage(pHandle uintptr, pid uint32, dllBytes []byte) (*RemoteImage, error) {
	if len(dllBytes) < 64 {
		return nil, fmt.Errorf("DLL too small (len=%d)", len(dllBytes))
	}
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))
	e_lfanew := *(*uint32)(unsafe.Pointer(dllPtr + 0x3C))
	if e_lfanew >= uint32(len(dllBytes)) || e_lfanew < 64 {
		return nil, fmt.Errorf("invalid e_lfanew: 0x%X", e_lfanew)
	}
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))
	if nt.Signature != 0x4550 {
		return nil, fmt.Errorf("invalid PE signature: 0x%X", nt.Signature)
	}
	return &RemoteImage{
		pHandle:       pHandle,
		pid:           pid,
		bytes:         dllBytes,
		dllPtr:        dllPtr,
		e_lfanew:      e_lfanew,
		nt:            nt,
		preferredBase: uintptr(nt.OptionalHeader.ImageBase),
		imageSize:     uintptr(nt.OptionalHeader.SizeOfImage),
	}, nil
}

// rvaToOffsetLocal translates an RVA using section headers (from local bytes).
func rvaToOffsetLocal(dllPtr uintptr, e_lfanew uint32, rva uint32) uintptr {
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))
	secStart := dllPtr + uintptr(e_lfanew) + unsafe.Sizeof(nt.Signature) + unsafe.Sizeof(nt.FileHeader) + unsafe.Sizeof(nt.OptionalHeader)
	for i := 0; i < int(nt.FileHeader.NumberOfSections); i++ {
		sh := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(secStart + uintptr(i)*unsafe.Sizeof(*(*IMAGE_SECTION_HEADER)(nil))))
		va := sh.VirtualAddress
		size := sh.SizeOfRawData
		if size == 0 {
			size = sh.VirtualSize
		}
		if rva >= va && rva < va+size {
			return uintptr(sh.PointerToRawData) + uintptr(rva-va)
		}
	}
	return uintptr(rva)
}

// cstringAtLocal reads a 0-terminated ASCII string from local bytes at a file offset base.
func cstringAtLocal(base uintptr) string {
	var bs []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(base + i))
		if b == 0 {
			break
		}
		bs = append(bs, b)
	}
	return string(bs)
}

func (ri *RemoteImage) allocImage() error {
	base := ri.preferredBase
	addr, err := api.Call("kernel32.dll", "VirtualAllocEx", ri.pHandle, base, ri.imageSize, uintptr(MEM_RESERVE|MEM_COMMIT), uintptr(PAGE_READWRITE))
	if err != nil || addr == 0 {
		addr, err = api.Call("kernel32.dll", "VirtualAllocEx", ri.pHandle, 0, ri.imageSize, uintptr(MEM_RESERVE|MEM_COMMIT), uintptr(PAGE_READWRITE))
		if err != nil || addr == 0 {
			return fmt.Errorf("VirtualAllocEx failed: %v", err)
		}
	}
	ri.base = addr
	return nil
}

func (ri *RemoteImage) writeHeadersAndSections() error {
	var written uintptr
	status, err := api.NtWriteVirtualMemory(ri.pHandle, ri.base, uintptr(unsafe.Pointer(&ri.bytes[0])), uintptr(ri.nt.OptionalHeader.SizeOfHeaders), &written)
	if err != nil || status != 0 {
		return fmt.Errorf("NtWriteVirtualMemory(headers) 0x%X err=%v", status, err)
	}
	numberOfSections := int(ri.nt.FileHeader.NumberOfSections)
	secAddr := ri.dllPtr + uintptr(ri.e_lfanew) + unsafe.Sizeof(ri.nt.Signature) + unsafe.Sizeof(ri.nt.OptionalHeader) + unsafe.Sizeof(ri.nt.FileHeader)
	for i := 0; i < numberOfSections; i++ {
		sh := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(secAddr))
		dst := ri.base + uintptr(sh.VirtualAddress)
		src := ri.dllPtr + uintptr(sh.PointerToRawData)
		if sh.SizeOfRawData > 0 {
			status, err = api.NtWriteVirtualMemory(ri.pHandle, dst, uintptr(src), uintptr(sh.SizeOfRawData), &written)
			if err != nil || status != 0 {
				return fmt.Errorf("NtWriteVirtualMemory(section %d) 0x%X err=%v", i, status, err)
			}
		}
		if sh.VirtualSize > sh.SizeOfRawData {
			zeroStart := dst + uintptr(sh.SizeOfRawData)
			zeroSize := uintptr(sh.VirtualSize - sh.SizeOfRawData)
			const chunk = 0x1000
			var w uintptr
			var zeroPage [chunk]byte
			for zeroSize > 0 {
				n := zeroSize
				if n > chunk {
					n = chunk
				}
				status, err = api.NtWriteVirtualMemory(ri.pHandle, zeroStart, uintptr(unsafe.Pointer(&zeroPage[0])), n, &w)
				if err != nil || status != 0 {
					return fmt.Errorf("NtWriteVirtualMemory(zero) 0x%X err=%v", status, err)
				}
				zeroStart += n
				zeroSize -= n
			}
		}
		secAddr += unsafe.Sizeof(*sh)
	}
	return nil
}

func (ri *RemoteImage) applyRelocations() error {
	delta := ri.base - ri.preferredBase
	if delta == 0 {
		return nil
	}
	relocDir := ri.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocDir.VirtualAddress == 0 || relocDir.Size == 0 {
		return fmt.Errorf("different base but no relocation table")
	}
	relocOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, relocDir.VirtualAddress)
	processed := 0
	for processed < int(relocDir.Size) {
		block := *(*BASE_RELOCATION_BLOCK)(unsafe.Pointer(ri.dllPtr + relocOff + uintptr(processed)))
		if block.BlockSize == 0 || block.BlockSize < 8 {
			break
		}
		cnt := int((block.BlockSize - 8) / 2)
		for i := 0; i < cnt; i++ {
			entry := *(*BASE_RELOCATION_ENTRY)(unsafe.Pointer(ri.dllPtr + relocOff + uintptr(processed) + 8 + uintptr(i*2)))
			if entry.Type() == 0 {
				continue
			}
			if entry.Type() != 10 {
				continue
			}
			rva := block.PageAddress + uint32(entry.Offset())
			addr := ri.base + uintptr(rva)
			buf := make([]byte, 8)
			status, err := api.NtReadVirtualMemory(ri.pHandle, addr, uintptr(unsafe.Pointer(&buf[0])), 8, nil)
			if err != nil || status != 0 {
				return fmt.Errorf("read reloc RVA 0x%X st=0x%X err=%v", rva, status, err)
			}
			cur := binary.LittleEndian.Uint64(buf)
			binary.LittleEndian.PutUint64(buf, cur+uint64(delta))
			status, err = api.NtWriteVirtualMemory(ri.pHandle, addr, uintptr(unsafe.Pointer(&buf[0])), 8, nil)
			if err != nil || status != 0 {
				return fmt.Errorf("write reloc RVA 0x%X st=0x%X err=%v", rva, status, err)
			}
		}
		processed += int(block.BlockSize)
	}
	return nil
}

func (ri *RemoteImage) resolveImports() error {
	impDir := ri.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	if impDir.VirtualAddress == 0 {
		return nil
	}
	impOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, impDir.VirtualAddress)
	for {
		imp := *(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(ri.dllPtr + impOff))
		if imp.Name == 0 {
			break
		}
		nameOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, imp.Name)
		dllName := cstringAtLocal(ri.dllPtr + nameOff)

		localBase, _ := GetLocalModuleBase(dllName)
		remoteBase, _ := RemoteGetModuleBaseByName(ri.pid, dllName)

		forcedHost := isApiSetName(dllName) || remoteBase == 0
		if !forcedHost && remoteBase == 0 {
			rb, lerr := LoadLibraryRemote(ri.pHandle, ri.pid, dllName)
			if lerr != nil || rb == 0 {
				return fmt.Errorf("failed to load %s in remote: %v", dllName, lerr)
			}
			remoteBase = rb
		}

		// Walk INT if present, otherwise IAT
		thunkRVA := imp.OriginalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = imp.FirstThunk
		}
		thunkOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, thunkRVA)
		iatRemote := ri.base + uintptr(imp.FirstThunk)

		for {
			lookup := *(*uint64)(unsafe.Pointer(ri.dllPtr + thunkOff))
			if lookup == 0 {
				break
			}
			var funcRVA uintptr
			resolvedRemote := remoteBase
			resolvedLocal := localBase

			resolveFromHosts := forcedHost || resolvedRemote == 0

			if (lookup & 0x8000000000000000) != 0 {
				// By ordinal
				name := fmt.Sprintf("#%d", lookup&0xFFFF)
				if resolveFromHosts {
					ok := false
					for _, host := range hostCandidateDLLs {
						hb, herr := GetLocalModuleBase(host)
						if herr != nil || hb == 0 {
							continue
						}
						if rva2, herr2 := GetLocalProcRVA(hb, name); herr2 == nil {
							rb, rerr := RemoteGetModuleBaseByName(ri.pid, host)
							if rerr != nil || rb == 0 {
								rb, rerr = LoadLibraryRemote(ri.pHandle, ri.pid, host)
								if rerr != nil || rb == 0 {
									continue
								}
							}
							resolvedLocal = hb
							resolvedRemote = rb
							funcRVA = rva2
							ok = true
							break
						}
					}
					if !ok {
						return fmt.Errorf("failed to resolve ordinal %s for %s", name, dllName)
					}
				} else {
					rrva, gerr := GetLocalProcRVA(resolvedLocal, name)
					if gerr != nil {
						return fmt.Errorf("GetLocalProcRVA ordinal %s!%s: %v", dllName, name, gerr)
					}
					funcRVA = rrva
				}
			} else {
				iibnOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, uint32(lookup))
				funcName := cstringAtLocal(ri.dllPtr + iibnOff + 2)
				if resolveFromHosts {
					ok := false
					for _, host := range hostCandidateDLLs {
						hb, herr := GetLocalModuleBase(host)
						if herr != nil || hb == 0 {
							continue
						}
						if rva2, herr2 := GetLocalProcRVA(hb, funcName); herr2 == nil {
							rb, rerr := RemoteGetModuleBaseByName(ri.pid, host)
							if rerr != nil || rb == 0 {
								rb, rerr = LoadLibraryRemote(ri.pHandle, ri.pid, host)
								if rerr != nil || rb == 0 {
									continue
								}
							}
							resolvedLocal = hb
							resolvedRemote = rb
							funcRVA = rva2
							ok = true
							break
						}
					}
					if !ok {
						return fmt.Errorf("failed to resolve %s for %s", funcName, dllName)
					}
				} else {
					rrva, gerr := GetLocalProcRVA(resolvedLocal, funcName)
					if gerr != nil {
						// Try forwarded export in local module if any
						if resolvedLocal != 0 {
							if fwdAddr, ok := checkForwardedExportByName(unsafe.Pointer(resolvedLocal), funcName); ok {
								fwdStr := cstringAt(fwdAddr)
								if realProc, rerr := resolveForwardedExport(fwdStr); rerr == nil && realProc != 0 {
									funcRVA = realProc - resolvedLocal
								}
							}
						}
						if funcRVA == 0 {
							// Probe hosts as a last resort
							for _, host := range hostCandidateDLLs {
								hb, herr := GetLocalModuleBase(host)
								if herr != nil || hb == 0 {
									continue
								}
								if rva2, herr2 := GetLocalProcRVA(hb, funcName); herr2 == nil {
									rb, rerr := RemoteGetModuleBaseByName(ri.pid, host)
									if rerr != nil || rb == 0 {
										rb, rerr = LoadLibraryRemote(ri.pHandle, ri.pid, host)
										if rerr != nil || rb == 0 {
											continue
										}
									}
									resolvedLocal = hb
									resolvedRemote = rb
									funcRVA = rva2
									break
								}
							}
							if funcRVA == 0 {
								return fmt.Errorf("GetLocalProcRVA %s!%s: %v", dllName, funcName, gerr)
							}
						}
					} else {
						funcRVA = rrva
					}
				}
			}

			if resolvedRemote == 0 {
				return fmt.Errorf("resolved remote base is zero for import from %s", dllName)
			}
			remoteVA := resolvedRemote + funcRVA
			procBytes := uintptrToBytes(remoteVA)
			var wrote uintptr
			status, err := api.NtWriteVirtualMemory(ri.pHandle, iatRemote, uintptr(unsafe.Pointer(&procBytes[0])), uintptr(len(procBytes)), &wrote)
			if err != nil || status != 0 {
				return fmt.Errorf("NtWriteVirtualMemory(IAT) 0x%X err=%v", status, err)
			}
			thunkOff += 8
			iatRemote += 8
		}
		impOff += 0x14
	}
	return nil
}

func (ri *RemoteImage) protectMemory() error {
	// headers R
	base := ri.base
	size := uintptr(ri.nt.OptionalHeader.SizeOfHeaders)
	var oldProt uintptr
	status, err := api.NtProtectVirtualMemory(ri.pHandle, &base, &size, PAGE_READONLY, &oldProt)
	if err != nil || status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory(headers) 0x%X err=%v", status, err)
	}
	const (
		IMAGE_SCN_MEM_EXECUTE = 0x20000000
		IMAGE_SCN_MEM_READ    = 0x40000000
		IMAGE_SCN_MEM_WRITE   = 0x80000000
	)
	secAddr := ri.dllPtr + uintptr(ri.e_lfanew) + unsafe.Sizeof(ri.nt.Signature) + unsafe.Sizeof(ri.nt.OptionalHeader) + unsafe.Sizeof(ri.nt.FileHeader)
	for i := 0; i < int(ri.nt.FileHeader.NumberOfSections); i++ {
		sh := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(secAddr))
		if sh.VirtualSize == 0 {
			secAddr += unsafe.Sizeof(*sh)
			continue
		}
		secBase := ri.base + uintptr(sh.VirtualAddress)
		secSize := uintptr(sh.VirtualSize)
		var prot uint32 = PAGE_READONLY
		flags := sh.Characteristics
		if (flags & IMAGE_SCN_MEM_WRITE) != 0 {
			prot = PAGE_READWRITE
		} else if (flags & IMAGE_SCN_MEM_EXECUTE) != 0 {
			prot = PAGE_EXECUTE_READ
		} else if (flags & IMAGE_SCN_MEM_READ) != 0 {
			prot = PAGE_READONLY
		}
		bb := secBase
		ss := secSize
		status, err = api.NtProtectVirtualMemory(ri.pHandle, &bb, &ss, uintptr(prot), &oldProt)
		if err != nil || status != 0 {
			return fmt.Errorf("NtProtectVirtualMemory(section %d) 0x%X err=%v", i, status, err)
		}
		secAddr += unsafe.Sizeof(*sh)
	}
	return nil
}

// callRemoteDllMainLike writes a small x64 stub to call target(dllBase, DLL_PROCESS_ATTACH, NULL).
func callRemoteDllMainLike(pHandle uintptr, dllBase uintptr, target uintptr) error {
	code := make([]byte, 0, 2+8+5+3+2+8+4+2+4+1)
	code = append(code, 0x48, 0xB9) // mov rcx, imm64
	code = append(code, uintptrToBytes(dllBase)...)
	code = append(code, 0xBA, 0x01, 0x00, 0x00, 0x00) // mov edx, 1
	code = append(code, 0x45, 0x31, 0xC0)             // xor r8d, r8d
	code = append(code, 0x48, 0xB8)                   // mov rax, imm64
	code = append(code, uintptrToBytes(target)...)
	code = append(code, 0x48, 0x83, 0xEC, 0x28) // sub rsp, 0x28
	code = append(code, 0xFF, 0xD0)             // call rax
	code = append(code, 0x48, 0x83, 0xC4, 0x28) // add rsp, 0x28
	code = append(code, 0xC3)                   // ret

	stub, err := api.Call("kernel32.dll", "VirtualAllocEx", pHandle, 0, uintptr(len(code)), uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_EXECUTE_READWRITE))
	if err != nil || stub == 0 {
		return fmt.Errorf("VirtualAllocEx(stub) failed: %v", err)
	}
	var written uintptr
	status, werr := api.NtWriteVirtualMemory(pHandle, stub, uintptr(unsafe.Pointer(&code[0])), uintptr(len(code)), &written)
	if werr != nil || status != 0 || written != uintptr(len(code)) {
		api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
		return fmt.Errorf("NtWriteVirtualMemory(stub) 0x%X err=%v", status, werr)
	}
	var threadId uintptr
	hThread, terr := api.Call("kernel32.dll", "CreateRemoteThread", pHandle, 0, 0, stub, 0, 0, uintptr(unsafe.Pointer(&threadId)))
	if terr != nil || hThread == 0 {
		api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
		return fmt.Errorf("CreateRemoteThread(stub) failed: %v", terr)
	}
	api.Call("kernel32.dll", "WaitForSingleObject", hThread, uintptr(^uint32(0)))
	api.Call("kernel32.dll", "CloseHandle", hThread)
	api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
	return nil
}

func (ri *RemoteImage) runTLSAndEntry(exportNameOpt string) {
    exportOnly := false
    if strings.HasPrefix(exportNameOpt, "export_only:") {
        exportOnly = true
        exportNameOpt = strings.TrimPrefix(exportNameOpt, "export_only:")
    }
    // TLS callbacks
    tlsDir := ri.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
	if tlsDir.VirtualAddress != 0 && tlsDir.Size >= uint32(unsafe.Sizeof(IMAGE_TLS_DIRECTORY64{})) {
		tlsOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, tlsDir.VirtualAddress)
		tls := (*IMAGE_TLS_DIRECTORY64)(unsafe.Pointer(ri.dllPtr + tlsOff))
		if tls.AddressOfCallBacks != 0 {
			callbacksRVA := uint32(uintptr(tls.AddressOfCallBacks) - uintptr(ri.preferredBase))
			cbOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, callbacksRVA)
			for idx := 0; ; idx++ {
				cbPref := *(*uint64)(unsafe.Pointer(ri.dllPtr + cbOff + uintptr(idx*8)))
				if cbPref == 0 {
					break
				}
				target := ri.base + uintptr(cbPref-uint64(ri.preferredBase))
				if err := callRemoteDllMainLike(ri.pHandle, ri.base, target); err != nil {
					log.Printf("[RemoteImage] TLS callback #%d failed: %v", idx, err)
				}
			}
		}
	}
    // DllMain unless export-only requested
    if !exportOnly {
        if ri.nt.OptionalHeader.AddressOfEntryPoint != 0 {
            entry := ri.base + uintptr(ri.nt.OptionalHeader.AddressOfEntryPoint)
            if err := callRemoteDllMainLike(ri.pHandle, ri.base, entry); err != nil {
                log.Printf("[RemoteImage] DllMain failed: %v", err)
            }
        }
    }

	// Optional export call
    if exportNameOpt == "" {
        return
    }
	expDir := ri.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if expDir.VirtualAddress == 0 || expDir.Size == 0 {
		log.Printf("[RemoteImage] no export directory; cannot call %s", exportNameOpt)
		return
	}
	expOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, expDir.VirtualAddress)
	exp := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(ri.dllPtr + expOff))
	funcsOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, exp.AddressOfFunctions)
	namesOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, exp.AddressOfNames)
	ordsOff := rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, exp.AddressOfNameOrdinals)

	var funcRVA uint32
	found := false
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(ri.dllPtr + namesOff + uintptr(i*4)))
		nm := cstringAtLocal(ri.dllPtr + rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, nameRVA))
		if nm == exportNameOpt {
			ord := *(*uint16)(unsafe.Pointer(ri.dllPtr + ordsOff + uintptr(i*2)))
			funcRVA = *(*uint32)(unsafe.Pointer(ri.dllPtr + funcsOff + uintptr(ord*4)))
			found = true
			break
		}
	}
	if !found {
		log.Printf("[RemoteImage] export not found: %s", exportNameOpt)
		return
	}
	var startAddr uintptr
	if funcRVA >= expDir.VirtualAddress && funcRVA < expDir.VirtualAddress+expDir.Size {
		fwdStr := cstringAtLocal(ri.dllPtr + rvaToOffsetLocal(ri.dllPtr, ri.e_lfanew, funcRVA))
		parts := strings.SplitN(fwdStr, ".", 2)
		if len(parts) == 2 {
			mod := parts[0]
			fn := parts[1]
			if !strings.HasSuffix(strings.ToLower(mod), ".dll") {
				mod += ".dll"
			}
			rb, _ := RemoteGetModuleBaseByName(ri.pid, mod)
			if rb == 0 {
				rb, _ = LoadLibraryRemote(ri.pHandle, ri.pid, mod)
			}
			if rb != 0 {
				hb, herr := GetLocalModuleBase(mod)
				if herr == nil && hb != 0 {
					if rrva, rerr := GetLocalProcRVA(hb, fn); rerr == nil {
						startAddr = rb + rrva
					}
				}
			}
		}
	} else {
		startAddr = ri.base + uintptr(funcRVA)
	}
	if startAddr == 0 {
		log.Printf("[RemoteImage] could not resolve start address for export %s", exportNameOpt)
		return
	}
	var threadId uintptr
	hThread, terr := api.Call("kernel32.dll", "CreateRemoteThread", ri.pHandle, 0, 0, startAddr, 0, 0, uintptr(unsafe.Pointer(&threadId)))
	if terr != nil || hThread == 0 {
		log.Printf("[RemoteImage] CreateRemoteThread for export %s failed: %v", exportNameOpt, terr)
		return
	}
	api.Call("kernel32.dll", "WaitForSingleObject", hThread, uintptr(^uint32(0)))
	api.Call("kernel32.dll", "CloseHandle", hThread)
}
