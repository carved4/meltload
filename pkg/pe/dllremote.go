package pe

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"unsafe"

	api "github.com/carved4/go-wincall"
)

// rvaToOffset translates an RVA within the image to a file offset inside dllBytes using section headers.
func rvaToOffset(dllPtr uintptr, e_lfanew uint32, rva uint32) uintptr {
	nt := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))
	// Section table start
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
	// If not found in sections (could be in headers), fall back to rva itself
	return uintptr(rva)
}

// cstringAtLocal reads a zero-terminated ASCII string from dllBytes at file offset.
func cstringAtLocal(base uintptr) string {
	var bs []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(base + i))
		if b == 0 { break }
		bs = append(bs, b)
	}
	return string(bs)
}

func LoadDLLRemote(pHandle uintptr, dllBytes []byte, functionIdentifier ...interface{}) (*DLLMapping, error) {
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))
	// Support optional functionIdentifier: treat missing as nil
	var fi interface{}
	if len(functionIdentifier) > 0 {
		fi = functionIdentifier[0]
	}

	if len(dllBytes) < 64 {
		return nil, fmt.Errorf("[ERROR] DLL file too small (less than 64 bytes)")
	}

	e_lfanew := *((*uint32)(unsafe.Pointer(dllPtr + 0x3c)))
	
	if e_lfanew >= uint32(len(dllBytes)) || e_lfanew < 64 {
		return nil, fmt.Errorf("[ERROR] Invalid e_lfanew offset: 0x%X", e_lfanew)
	}
	
	nt_header := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))
	
	if nt_header.Signature != 0x4550 {
		return nil, fmt.Errorf("[ERROR] Invalid PE signature: 0x%X", nt_header.Signature)
	}

	preferredBase := uintptr(nt_header.OptionalHeader.ImageBase)
	regionSize := uintptr(nt_header.OptionalHeader.SizeOfImage)
	
	// Remote mapping: no local encryption of remote memory

	dllBase := preferredBase
	addr, err := api.Call("kernel32.dll", "VirtualAllocEx", pHandle, dllBase, regionSize, uintptr(MEM_RESERVE|MEM_COMMIT), uintptr(PAGE_READWRITE))
	if err != nil || addr == 0 {
		// fallback without preferred base
		regionSize = uintptr(nt_header.OptionalHeader.SizeOfImage)
		addr, err = api.Call("kernel32.dll", "VirtualAllocEx", pHandle, 0, regionSize, uintptr(MEM_RESERVE|MEM_COMMIT), uintptr(PAGE_READWRITE))
		if err != nil || addr == 0 {
			return nil, fmt.Errorf("[ERROR] VirtualAllocEx failed: err=%v", err)
		}
	}
	dllBase = addr

	var numberOfBytesWritten uintptr
	status, err := api.NtWriteVirtualMemory(pHandle, dllBase, uintptr(unsafe.Pointer(&dllBytes[0])), uintptr(nt_header.OptionalHeader.SizeOfHeaders), &numberOfBytesWritten)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtWriteVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}
	numberOfSections := int(nt_header.FileHeader.NumberOfSections)

	var sectionAddr uintptr
	sectionAddr = dllPtr + uintptr(e_lfanew) + unsafe.Sizeof(nt_header.Signature) + unsafe.Sizeof(nt_header.OptionalHeader) + unsafe.Sizeof(nt_header.FileHeader)

	for i := 0; i < numberOfSections; i++ {
		section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionAddr))
		sectionDestination := dllBase + uintptr(section.VirtualAddress)
		sectionBytes := (*byte)(unsafe.Pointer(dllPtr + uintptr(section.PointerToRawData)))

		// Copy initialized data
		if section.SizeOfRawData > 0 {
			status, err = api.NtWriteVirtualMemory(pHandle, sectionDestination, uintptr(unsafe.Pointer(sectionBytes)), uintptr(section.SizeOfRawData), &numberOfBytesWritten)
			if err != nil || status != 0 {
				log.Fatalf("[ERROR] NtWriteVirtualMemory Failed: status=0x%X, err=%v", status, err)
			}
		}
		// Zero the remaining VirtualSize for .bss (if any)
		if section.VirtualSize > section.SizeOfRawData {
			zeroStart := sectionDestination + uintptr(section.SizeOfRawData)
			zeroSize := uintptr(section.VirtualSize - section.SizeOfRawData)
			// Create zeroed buffer on the fly in chunks to avoid huge allocs (simple approach here)
			const chunk = 0x1000
			var written uintptr
			for zeroSize > 0 {
				n := zeroSize
				if n > chunk {
					n = chunk
				}
				// Reuse a static zero page by allocating once
				var zeroPage [chunk]byte
				status, err = api.NtWriteVirtualMemory(pHandle, zeroStart, uintptr(unsafe.Pointer(&zeroPage[0])), n, &written)
				if err != nil || status != 0 {
					log.Fatalf("[ERROR] NtWriteVirtualMemory (zero) Failed: status=0x%X, err=%v", status, err)
				}
				zeroStart += n
				zeroSize -= n
			}
		}
		sectionAddr += unsafe.Sizeof(*section)
	}

	deltaImageBase := dllBase - preferredBase
	if deltaImageBase != 0 {
		relocDir := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		if relocDir.VirtualAddress == 0 || relocDir.Size == 0 {
			return nil, fmt.Errorf("[ERROR] DLL loaded at different base address but no relocation table found")
		}
		// Parse relocation data from local dllBytes using file offsets
		relocOff := rvaToOffset(dllPtr, e_lfanew, relocDir.VirtualAddress)
		processed := 0
		for processed < int(relocDir.Size) {
			block := *(*BASE_RELOCATION_BLOCK)(unsafe.Pointer(dllPtr + relocOff + uintptr(processed)))
			if block.BlockSize == 0 || block.BlockSize < 8 {
				break
			}
			entriesOff := uintptr(processed) + 8
			count := int((block.BlockSize - 8) / 2)
			for i := 0; i < count; i++ {
				entry := *(*BASE_RELOCATION_ENTRY)(unsafe.Pointer(dllPtr + relocOff + entriesOff + uintptr(i*2)))
				t := entry.Type()
				if t == 0 { // IMAGE_REL_BASED_ABSOLUTE: skip
					continue
				}
				if t != 10 { // IMAGE_REL_BASED_DIR64 on x64
					continue
				}
				relocationRVA := block.PageAddress + uint32(entry.Offset())
				addressLocation := dllBase + uintptr(relocationRVA)
				// Read, adjust, write back in remote process
				buf := make([]byte, 8)
				status, err := api.NtReadVirtualMemory(pHandle, addressLocation, uintptr(unsafe.Pointer(&buf[0])), 8, nil)
				if err != nil || status != 0 {
					return nil, fmt.Errorf("[ERROR] Failed to read relocation at RVA 0x%X: status=0x%X, err=%v", relocationRVA, status, err)
				}
				cur := binary.LittleEndian.Uint64(buf)
				newv := cur + uint64(deltaImageBase)
				binary.LittleEndian.PutUint64(buf, newv)
				status, err = api.NtWriteVirtualMemory(pHandle, addressLocation, uintptr(unsafe.Pointer(&buf[0])), 8, nil)
				if err != nil || status != 0 {
					return nil, fmt.Errorf("[ERROR] Failed to write relocation at RVA 0x%X: status=0x%X, err=%v", relocationRVA, status, err)
				}
			}
			processed += int(block.BlockSize)
		}
	}
	// Resolve imports by reading descriptors from local dllBytes and writing remote VA = remoteBase + RVA into IAT
	importsDirectory := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	if importsDirectory.VirtualAddress != 0 {
		// Determine target PID from handle
		pid, pidErr := GetProcessIdFromHandle(pHandle)
		if pidErr != nil {
			return nil, fmt.Errorf("failed to get PID from handle: %v", pidErr)
		}
		// Walk IMAGE_IMPORT_DESCRIPTOR array from local dllBytes
		impDescOff := rvaToOffset(dllPtr, e_lfanew, importsDirectory.VirtualAddress)
		for {
			imp := *(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(dllPtr + impDescOff))
			if imp.Name == 0 { break }

			nameOff := rvaToOffset(dllPtr, e_lfanew, imp.Name)
			dllName := cstringAtLocal(dllPtr + nameOff)

			// Ensure module is loaded locally and get local base (loads dependencies like VCRUNTIME140.dll when present)
			localBase, lerr := GetLocalModuleBase(dllName)
			if lerr != nil {
				// API set DLLs like api-ms-win-... are not loadable; we'll resolve from host modules per symbol
				localBase = 0
			}
			// Get remote base in target process (load it if missing), but skip LoadLibrary for API Set contracts
			remoteBase, rerr := RemoteGetModuleBaseByName(pid, dllName)
			if rerr != nil || remoteBase == 0 {
				if isApiSetName(dllName) {
					remoteBase = 0
				} else {
					rb, lerr2 := LoadLibraryRemote(pHandle, pid, dllName)
					if lerr2 != nil || rb == 0 {
						return nil, fmt.Errorf("remote module not found and load failed for %s: %v", dllName, lerr2)
					}
					remoteBase = rb
				}
			}

            // Choose INT (OriginalFirstThunk) if present, otherwise IAT
            thunkRVA := imp.OriginalFirstThunk
            if thunkRVA == 0 { thunkRVA = imp.FirstThunk }
            thunkOff := rvaToOffset(dllPtr, e_lfanew, thunkRVA)
            // Remote IAT address to write into
            iatRemote := dllBase + uintptr(imp.FirstThunk)

            for {
                lookup := *(*uint64)(unsafe.Pointer(dllPtr + thunkOff))
                if lookup == 0 { break }

                var funcRVA uintptr
                var resolvedRemoteBase uintptr = remoteBase
                var resolvedLocalBase uintptr = localBase
                forcedHostResolve := isApiSetName(dllName) || resolvedRemoteBase == 0

                if (lookup & 0x8000000000000000) != 0 {
                    // import by ordinal
                    ordinal := lookup & 0xFFFF
                    name := fmt.Sprintf("#%d", ordinal)
                    if forcedHostResolve {
                        // Try candidates directly since api-set or missing remote base
                        candidates := []string{"ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcrt.dll", "kernel32.dll", "ntdll.dll"}
                        resolved := false
                        for _, host := range candidates {
                            hb, herr := GetLocalModuleBase(host)
                            if herr != nil || hb == 0 { continue }
                            if rva2, herr2 := GetLocalProcRVA(hb, name); herr2 == nil {
                                rb, rerr2 := RemoteGetModuleBaseByName(pid, host)
                                if rerr2 != nil || rb == 0 {
                                    rb, rerr2 = LoadLibraryRemote(pHandle, pid, host)
                                    if rerr2 != nil || rb == 0 { continue }
                                }
                                resolvedLocalBase = hb
                                resolvedRemoteBase = rb
                                funcRVA = rva2
                                resolved = true
                                break
                            }
                        }
                        if !resolved {
                            return nil, fmt.Errorf("failed to resolve ordinal %s from candidates for %s", name, dllName)
                        }
                    } else {
                        rrva, gerr := GetLocalProcRVA(localBase, name)
                        if gerr != nil {
                            return nil, fmt.Errorf("GetLocalProcRVA ordinal failed for %s!%s: %v", dllName, name, gerr)
                        }
                        funcRVA = rrva
                    }
                } else {
                    iibnOff := rvaToOffset(dllPtr, e_lfanew, uint32(lookup))
                    // skip Hint (2 bytes) then ASCII name
                    functionName := cstringAtLocal(dllPtr + iibnOff + 2)

                    if forcedHostResolve {
                        // Probe host candidates, prefer CRT hosts first
                        candidates := []string{"ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcrt.dll", "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"}
                        resolved := false
                        for _, host := range candidates {
                            hb, herr := GetLocalModuleBase(host)
                            if herr != nil || hb == 0 { continue }
                            if rva2, herr2 := GetLocalProcRVA(hb, functionName); herr2 == nil {
                                // ensure remote host is present
                                rb, rerr2 := RemoteGetModuleBaseByName(pid, host)
                                if rerr2 != nil || rb == 0 {
                                    rb, rerr2 = LoadLibraryRemote(pHandle, pid, host)
                                    if rerr2 != nil || rb == 0 { continue }
                                }
                                resolvedLocalBase = hb
                                resolvedRemoteBase = rb
                                funcRVA = rva2
                                resolved = true
                                break
                            }
                        }
                        if !resolved {
                            return nil, fmt.Errorf("failed to resolve %s from candidates for %s", functionName, dllName)
                        }
                    } else {
                        rrva, gerr := GetLocalProcRVA(localBase, functionName)
                        if gerr != nil {
                            // Try forwarder resolution using existing helpers on local module base
                            if resolvedLocalBase != 0 {
                                if fwdAddr, ok := checkForwardedExportByName(unsafe.Pointer(resolvedLocalBase), functionName); ok {
                                    fwdStr := cstringAt(fwdAddr)
                                    realProc, rerr := resolveForwardedExport(fwdStr)
                                    if rerr == nil && realProc != 0 {
                                        funcRVA = realProc - resolvedLocalBase
                                    } else {
                                        funcRVA = 0
                                    }
                                }
                            }
                            if funcRVA == 0 {
                                // Probe host candidates for other missing-module cases
                                candidates := []string{"ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcrt.dll", "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"}
                                for _, host := range candidates {
                                    hb, herr := GetLocalModuleBase(host)
                                    if herr != nil || hb == 0 { continue }
                                    if rva2, herr2 := GetLocalProcRVA(hb, functionName); herr2 == nil {
                                        // ensure remote host is present
                                        rb, rerr2 := RemoteGetModuleBaseByName(pid, host)
                                        if rerr2 != nil || rb == 0 {
                                            rb, rerr2 = LoadLibraryRemote(pHandle, pid, host)
                                            if rerr2 != nil || rb == 0 { continue }
                                        }
                                        resolvedLocalBase = hb
                                        resolvedRemoteBase = rb
                                        funcRVA = rva2
                                        break
                                    }
                                }
                                if funcRVA == 0 {
                                    return nil, fmt.Errorf("GetLocalProcRVA failed for %s!%s: %v", dllName, functionName, gerr)
                                }
                            }
                        } else {
                            funcRVA = rrva
                        }
                    }
                }

                // Use the resolved remote base (must be non-zero)
                if resolvedRemoteBase == 0 {
                    return nil, fmt.Errorf("resolved remote base is zero for %s import; refusing to write IAT", dllName)
                }
                remoteVA := resolvedRemoteBase + funcRVA
                procBytes := uintptrToBytes(remoteVA)
                var written uintptr
                status, err := api.NtWriteVirtualMemory(pHandle, iatRemote, uintptr(unsafe.Pointer(&procBytes[0])), uintptr(len(procBytes)), &written)
                if err != nil || status != 0 { log.Fatalf("[ERROR] NtWriteVirtualMemory(IAT) Failed: status=0x%X, err=%v", status, err) }
                // advance
                thunkOff += 8
                iatRemote += 8
            }
            impDescOff += 0x14
        }
    }

    // Set proper protections: headers R, .text RX, .rdata R, .data/.pdata RW, etc.
    // Protect headers as read-only
    {
        base := dllBase
        size := uintptr(nt_header.OptionalHeader.SizeOfHeaders)
        var oldProt uintptr
        status, err := api.NtProtectVirtualMemory(pHandle, &base, &size, PAGE_READONLY, &oldProt)
        if err != nil || status != 0 {
            log.Fatalf("[ERROR] NtProtectVirtualMemory (headers) Failed: status=0x%X, err=%v", status, err)
        }
    }
    // Section flag masks
    const (
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ    = 0x40000000
        IMAGE_SCN_MEM_WRITE   = 0x80000000
    )
    // Iterate sections and set per-section protection
    {
        numberOfSections := int(nt_header.FileHeader.NumberOfSections)
        sectionAddr := dllPtr + uintptr(e_lfanew) + unsafe.Sizeof(nt_header.Signature) + unsafe.Sizeof(nt_header.OptionalHeader) + unsafe.Sizeof(nt_header.FileHeader)
        for i := 0; i < numberOfSections; i++ {
            section := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionAddr))
            if section.VirtualSize == 0 {
                sectionAddr += unsafe.Sizeof(*section)
                continue
            }
            secBase := dllBase + uintptr(section.VirtualAddress)
            secSize := uintptr(section.VirtualSize)
            // Round up to page size implicitly handled by NtProtectVirtualMemory
            var prot uint32 = PAGE_READONLY
            flags := section.Characteristics
            if (flags & IMAGE_SCN_MEM_WRITE) != 0 {
                prot = PAGE_READWRITE
            } else if (flags & IMAGE_SCN_MEM_EXECUTE) != 0 {
                prot = PAGE_EXECUTE_READ
            } else if (flags & IMAGE_SCN_MEM_READ) != 0 {
                prot = PAGE_READONLY
            }
            base := secBase
            size := secSize
            var oldProt uintptr
            status, err := api.NtProtectVirtualMemory(pHandle, &base, &size, uintptr(prot), &oldProt)
            if err != nil || status != 0 {
                log.Fatalf("[ERROR] NtProtectVirtualMemory (section %d) Failed: status=0x%X, err=%v", i, status, err)
            }
            sectionAddr += unsafe.Sizeof(*section)
        }
    }

    // If no explicit export is requested, run TLS callbacks (if any) and DllMain(DLL_PROCESS_ATTACH)
    // We avoid dereferencing remote memory by parsing TLS directory from local bytes, which stores
    // preferred-base VAs; we translate to the remote image base.
    if fi == nil || (func() bool { s, ok := fi.(string); return ok && s == "" })() {
        // 1) TLS callbacks
        tlsDir := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
        if tlsDir.VirtualAddress != 0 && tlsDir.Size >= uint32(unsafe.Sizeof(IMAGE_TLS_DIRECTORY64{})) {
            tlsOff := rvaToOffset(dllPtr, e_lfanew, tlsDir.VirtualAddress)
            tls := (*IMAGE_TLS_DIRECTORY64)(unsafe.Pointer(dllPtr + tlsOff))
            if tls.AddressOfCallBacks != 0 {
                // AddressOfCallBacks is a VA at preferred base. Convert to file offset and enumerate until NULL.
                callbacksRVA := uint32(uintptr(tls.AddressOfCallBacks) - uintptr(preferredBase))
                cbOff := rvaToOffset(dllPtr, e_lfanew, callbacksRVA)
                for idx := 0; ; idx++ {
                    cbPreferred := *(*uint64)(unsafe.Pointer(dllPtr + cbOff + uintptr(idx*8)))
                    if cbPreferred == 0 { break }
                    // Translate to remote VA
                    target := dllBase + uintptr(cbPreferred-uint64(preferredBase))
                    if err := callRemoteDllMainLike(pHandle, dllBase, target); err != nil {
                        log.Printf("[LoadDLLRemote] TLS callback #%d failed: %v", idx, err)
                    } else {
                        log.Printf("[LoadDLLRemote] TLS callback #%d executed", idx)
                    }
                }
            }
        }

        // 2) DllMain
        if nt_header.OptionalHeader.AddressOfEntryPoint != 0 {
            entry := dllBase + uintptr(nt_header.OptionalHeader.AddressOfEntryPoint)
            if err := callRemoteDllMainLike(pHandle, dllBase, entry); err != nil {
                log.Printf("[LoadDLLRemote] DllMain call failed: %v", err)
            } else {
                log.Printf("[LoadDLLRemote] DllMain(DLL_PROCESS_ATTACH) executed")
            }
        }
    }

    // Optional: call a single export if requested (by name). No remote memory deref.
    if fi != nil {
        if exportName, ok := fi.(string); ok && exportName != "" {
            expDir := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            if expDir.VirtualAddress != 0 && expDir.Size != 0 {
                expOff := rvaToOffset(dllPtr, e_lfanew, expDir.VirtualAddress)
                exp := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(dllPtr + expOff))
                funcsOff := rvaToOffset(dllPtr, e_lfanew, exp.AddressOfFunctions)
                namesOff := rvaToOffset(dllPtr, e_lfanew, exp.AddressOfNames)
                ordsOff := rvaToOffset(dllPtr, e_lfanew, exp.AddressOfNameOrdinals)

                var funcRVA uint32
                found := false
                for i := uint32(0); i < exp.NumberOfNames; i++ {
                    nameRVA := *(*uint32)(unsafe.Pointer(dllPtr + namesOff + uintptr(i*4)))
                    nm := cstringAtLocal(dllPtr + rvaToOffset(dllPtr, e_lfanew, nameRVA))
                    if nm == exportName {
                        ord := *(*uint16)(unsafe.Pointer(dllPtr + ordsOff + uintptr(i*2)))
                        funcRVA = *(*uint32)(unsafe.Pointer(dllPtr + funcsOff + uintptr(ord*4)))
                        found = true
                        break
                    }
                }
                if !found {
                    log.Printf("[LoadDLLRemote] export not found: %s (skipping call)", exportName)
                } else {
                    // Handle forwarded export if RVA points inside export directory range
                    var startAddr uintptr
                    if funcRVA >= expDir.VirtualAddress && funcRVA < expDir.VirtualAddress+expDir.Size {
                        fwdStr := cstringAtLocal(dllPtr + rvaToOffset(dllPtr, e_lfanew, funcRVA))
                        parts := strings.SplitN(fwdStr, ".", 2)
                        if len(parts) == 2 {
                            mod := parts[0]
                            fn := parts[1]
                            if !strings.HasSuffix(strings.ToLower(mod), ".dll") { mod += ".dll" }
                            // Resolve remote base of forward target
                            pid, pidErr := GetProcessIdFromHandle(pHandle)
                            if pidErr == nil {
                                rb, _ := RemoteGetModuleBaseByName(pid, mod)
                                if rb == 0 {
                                    rb, _ = LoadLibraryRemote(pHandle, pid, mod)
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
                        }
                    } else {
                        startAddr = dllBase + uintptr(funcRVA)
                    }

                    if startAddr != 0 {
                        var threadId uintptr
                        hThread, terr := api.Call("kernel32.dll", "CreateRemoteThread", pHandle, 0, 0, startAddr, 0, 0, uintptr(unsafe.Pointer(&threadId)))
                        if terr != nil || hThread == 0 {
                            log.Printf("[LoadDLLRemote] CreateRemoteThread for export %s failed: %v", exportName, terr)
                        } else {
                            api.Call("kernel32.dll", "WaitForSingleObject", hThread, uintptr(^uint32(0))) // INFINITE
                            api.Call("kernel32.dll", "CloseHandle", hThread)
                        }
                    } else {
                        log.Printf("[LoadDLLRemote] could not resolve start address for export %s", exportName)
                    }
                }
            } else {
                log.Printf("[LoadDLLRemote] no export directory present; cannot call %s", exportName)
            }
        }
    }

    mapping := createDLLMapping(dllBase, uintptr(nt_header.OptionalHeader.SizeOfImage))

    return mapping, nil
}

// callRemoteDllMainLike writes a tiny x64 stub into the target that sets RCX=dllBase, EDX=DLL_PROCESS_ATTACH,
// R8=NULL and calls the target function address, then returns. This is suitable for DllMain and TLS callbacks.
func callRemoteDllMainLike(pHandle uintptr, dllBase uintptr, target uintptr) error {
    // x64 stub:
    //   48 B9 <imm64 dllBase>        mov rcx, dllBase                     ; hModule
    //   BA 01 00 00 00               mov edx, 1                           ; DLL_PROCESS_ATTACH
    //   45 31 C0                     xor r8d, r8d                         ; lpReserved=NULL
    //   48 B8 <imm64 target>         mov rax, target
    //   48 83 EC 28                  sub rsp, 0x28                        ; shadow space + align
    //   FF D0                        call rax
    //   48 83 C4 28                  add rsp, 0x28
    //   C3                           ret
    code := make([]byte, 0, 2+8+5+3+2+8+4+2+4+1)
    // mov rcx, imm64
    code = append(code, 0x48, 0xB9)
    code = append(code, uintptrToBytes(dllBase)...)
    // mov edx, 1
    code = append(code, 0xBA, 0x01, 0x00, 0x00, 0x00)
    // xor r8d, r8d
    code = append(code, 0x45, 0x31, 0xC0)
    // mov rax, imm64
    code = append(code, 0x48, 0xB8)
    code = append(code, uintptrToBytes(target)...)
    // sub rsp, 0x28
    code = append(code, 0x48, 0x83, 0xEC, 0x28)
    // call rax
    code = append(code, 0xFF, 0xD0)
    // add rsp, 0x28
    code = append(code, 0x48, 0x83, 0xC4, 0x28)
    // ret
    code = append(code, 0xC3)

    // Allocate RX memory in remote and write the stub
    stub, err := api.Call("kernel32.dll", "VirtualAllocEx", pHandle, 0, uintptr(len(code)), uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_EXECUTE_READWRITE))
    if err != nil || stub == 0 {
        return fmt.Errorf("VirtualAllocEx for stub failed: %v", err)
    }
    var written uintptr
    status, werr := api.NtWriteVirtualMemory(pHandle, stub, uintptr(unsafe.Pointer(&code[0])), uintptr(len(code)), &written)
    if werr != nil || status != 0 || written != uintptr(len(code)) {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
        return fmt.Errorf("NtWriteVirtualMemory for stub failed: status=0x%X err=%v", status, werr)
    }
    // Create remote thread at stub
    var threadId uintptr
    hThread, terr := api.Call("kernel32.dll", "CreateRemoteThread", pHandle, 0, 0, stub, 0, 0, uintptr(unsafe.Pointer(&threadId)))
    if terr != nil || hThread == 0 {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
        return fmt.Errorf("CreateRemoteThread for stub failed: %v", terr)
    }
    api.Call("kernel32.dll", "WaitForSingleObject", hThread, uintptr(^uint32(0))) // INFINITE
    api.Call("kernel32.dll", "CloseHandle", hThread)
    api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
    return nil
}
