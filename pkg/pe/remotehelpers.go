package pe

import (
    "errors"
    "strings"
    "unicode/utf16"
    "unsafe"

    api "github.com/carved4/go-wincall"
)

const (
    TH32CS_SNAPMODULE   = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
)

type MODULEENTRY32 struct {
    DwSize        uint32
    Th32ModuleID  uint32
    Th32ProcessID uint32
    GlblcntUsage  uint32
    ProccntUsage  uint32
    ModBaseAddr   uintptr
    ModBaseSize   uint32
    HModule       uintptr
    SzModule      [256]uint16
    SzExePath     [260]uint16
}

// isApiSetName reports whether the DLL name is an API Set contract (not loadable via LoadLibrary).
func isApiSetName(name string) bool {
    n := strings.ToLower(name)
    return strings.HasPrefix(n, "api-ms-win-") || strings.HasPrefix(n, "ext-ms-")
}

// LoadLibraryRemote ensures a DLL is loaded in the remote process. Returns the remote module base.
func LoadLibraryRemote(pHandle uintptr, pid uint32, moduleName string) (uintptr, error) {
    // Allocate remote memory for ANSI string
    nameA := append([]byte(moduleName), 0)
    size := uintptr(len(nameA))
    remoteBuf, err := api.Call("kernel32.dll", "VirtualAllocEx", pHandle, 0, size, uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_READWRITE))
    if err != nil || remoteBuf == 0 {
        return 0, errors.New("VirtualAllocEx failed for DLL name")
    }
    // Write the string
    var written uintptr
    status, werr := api.NtWriteVirtualMemory(pHandle, remoteBuf, uintptr(unsafe.Pointer(&nameA[0])), size, &written)
    if werr != nil || status != 0 || written != size {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, remoteBuf, 0, uintptr(MEM_RELEASE))
        return 0, errors.New("NtWriteVirtualMemory failed for DLL name")
    }

    // Compute remote address of LoadLibraryA
    k32Local, lerr := GetLocalModuleBase("kernel32.dll")
    if lerr != nil { return 0, lerr }
    rva, perr := GetLocalProcRVA(k32Local, "LoadLibraryA")
    if perr != nil { return 0, perr }
    k32Remote, rerr := RemoteGetModuleBaseByName(pid, "KERNEL32.dll")
    if rerr != nil || k32Remote == 0 {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, remoteBuf, 0, uintptr(MEM_RELEASE))
        return 0, errors.New("remote KERNEL32.dll not found")
    }
    startAddr := k32Remote + rva

    // Create remote thread to call LoadLibraryA(moduleName)
    var threadId uintptr
    hThread, terr := api.Call("kernel32.dll", "CreateRemoteThread", pHandle, 0, 0, startAddr, remoteBuf, 0, uintptr(unsafe.Pointer(&threadId)))
    if terr != nil || hThread == 0 {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, remoteBuf, 0, uintptr(MEM_RELEASE))
        return 0, errors.New("CreateRemoteThread failed")
    }
    // Wait for completion
    api.Call("kernel32.dll", "WaitForSingleObject", hThread, uintptr(^uint32(0))) // INFINITE
    api.Call("kernel32.dll", "CloseHandle", hThread)
    api.Call("kernel32.dll", "VirtualFreeEx", pHandle, remoteBuf, 0, uintptr(MEM_RELEASE))

    // Re-query the module base
    base, berr := RemoteGetModuleBaseByName(pid, moduleName)
    if berr != nil || base == 0 {
        return 0, errors.New("module still not loaded after LoadLibraryA: " + moduleName)
    }
    return base, nil
}

func utf16ToString(buf []uint16) string {
    n := 0
    for n < len(buf) && buf[n] != 0 {
        n++
    }
    return string(utf16.Decode(buf[:n]))
}

// GetProcessIdFromHandle returns the PID for a process HANDLE.
func GetProcessIdFromHandle(hProcess uintptr) (uint32, error) {
    pid, err := api.Call("kernel32.dll", "GetProcessId", hProcess)
    if err != nil || pid == 0 {
        return 0, errors.New("GetProcessId failed")
    }
    return uint32(pid), nil
}

// RemoteGetModuleBaseByName finds a module base in a remote process by name (case-insensitive).
func RemoteGetModuleBaseByName(pid uint32, moduleName string) (uintptr, error) {
    snap, err := api.Call("kernel32.dll", "CreateToolhelp32Snapshot", uintptr(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32), uintptr(pid))
    if err != nil || snap == 0 || snap == ^uintptr(0) {
        return 0, errors.New("CreateToolhelp32Snapshot failed")
    }
    defer api.Call("kernel32.dll", "CloseHandle", snap)

    var me MODULEENTRY32
    me.DwSize = uint32(unsafe.Sizeof(me))

    ok, _ := api.Call("kernel32.dll", "Module32FirstW", snap, uintptr(unsafe.Pointer(&me)))
    if ok == 0 {
        return 0, errors.New("Module32FirstW failed")
    }

    target := strings.ToLower(moduleName)
    for {
        name := strings.ToLower(utf16ToString(me.SzModule[:]))
        if name == target {
            return me.ModBaseAddr, nil
        }
        ok, _ = api.Call("kernel32.dll", "Module32NextW", snap, uintptr(unsafe.Pointer(&me)))
        if ok == 0 {
            break
        }
    }
    return 0, errors.New("module not found: " + moduleName)
}

// GetLocalModuleBase ensures the module is loaded locally and returns its HMODULE.
func GetLocalModuleBase(moduleName string) (uintptr, error) {
    // Try GetModuleHandleA first
    nameA := append([]byte(moduleName), 0)
    h, _ := api.Call("kernel32.dll", "GetModuleHandleA", uintptr(unsafe.Pointer(&nameA[0])))
    if h != 0 {
        return h, nil
    }
    // LoadLibraryA if not present
    h, err := api.Call("kernel32.dll", "LoadLibraryA", uintptr(unsafe.Pointer(&nameA[0])))
    if err != nil || h == 0 {
        return 0, errors.New("failed to load module locally: " + moduleName)
    }
    return h, nil
}

// GetLocalProcRVA returns the RVA of a proc within a local module.
// If import is by ordinal, pass name as "#<ordinal>" (e.g., "#12").
func GetLocalProcRVA(hModule uintptr, name string) (uintptr, error) {
    if len(name) > 0 && name[0] == '#' {
        // ordinal
        var ord uint64 = 0
        for i := 1; i < len(name); i++ {
            c := name[i]
            if c < '0' || c > '9' { break }
            ord = ord*10 + uint64(c-'0')
        }
        proc, err := api.Call("kernel32.dll", "GetProcAddress", hModule, uintptr(ord))
        if err != nil || proc == 0 {
            return 0, errors.New("GetProcAddress by ordinal failed")
        }
        return proc - hModule, nil
    }
    nm := append([]byte(name), 0)
    proc, err := api.Call("kernel32.dll", "GetProcAddress", hModule, uintptr(unsafe.Pointer(&nm[0])))
    if err != nil || proc == 0 {
        return 0, errors.New("GetProcAddress failed for " + name)
    }
    return proc - hModule, nil
}
