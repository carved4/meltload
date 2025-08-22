
package pe

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/carved4/go-wincall"
)

type ProcessEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16 // MAX_PATH in UTF-16
}

type ThreadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}


// FindTargetProcess finds a process by name and returns its PID and handle
func FindTargetProcess(processName string) (uint32, uintptr, error) {
	dllHash := wincall.GetHash("kernel32.dll")
	moduleBase := wincall.GetModuleBase(dllHash)

	createToolhelp32SnapshotHash := wincall.GetHash("CreateToolhelp32Snapshot")
	createToolhelp32SnapshotAddr := wincall.GetFunctionAddress(moduleBase, createToolhelp32SnapshotHash)

	process32FirstHash := wincall.GetHash("Process32FirstW")
	process32FirstAddr := wincall.GetFunctionAddress(moduleBase, process32FirstHash)

	process32NextHash := wincall.GetHash("Process32NextW")
	process32NextAddr := wincall.GetFunctionAddress(moduleBase, process32NextHash)

	closeHandleHash := wincall.GetHash("CloseHandle")
	closeHandleAddr := wincall.GetFunctionAddress(moduleBase, closeHandleHash)

	openProcessHash := wincall.GetHash("OpenProcess")
	openProcessAddr := wincall.GetFunctionAddress(moduleBase, openProcessHash)

	snapshot, _ := wincall.CallG0(createToolhelp32SnapshotAddr, 0x00000002, 0)
	if snapshot == 0 {
		return 0, 0, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer wincall.CallG0(closeHandleAddr, snapshot)

	var pe ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	processName = strings.ToLower(processName)
	var matches []ProcessEntry32

	result, _ := wincall.CallG0(process32FirstAddr, snapshot, uintptr(unsafe.Pointer(&pe)))
	if result == 0 {
		return 0, 0, fmt.Errorf("Process32First failed")
	}

	for {
		currentName := ""
		for i := 0; i < len(pe.ExeFile); i++ {
			if pe.ExeFile[i] == 0 {
				break
			}
			currentName += string(rune(pe.ExeFile[i]))
		}

		if strings.Contains(strings.ToLower(currentName), processName) {
			matches = append(matches, pe)
		}

		result, _ = wincall.CallG0(process32NextAddr, snapshot, uintptr(unsafe.Pointer(&pe)))
		if result == 0 {
			break
		}
	}

	if len(matches) == 0 {
		return 0, 0, fmt.Errorf("no process found matching '%s'", processName)
	}

	if len(matches) > 1 {
		// Common case: multiple matches; select the first one deterministically
		fmt.Printf("[!] Multiple processes found matching '%s', selecting the first match (PID=%d)\n", processName, matches[0].ProcessID)
	}

	targetProc := matches[0]
	handle, _ := wincall.CallG0(openProcessAddr, 0x1FFFFF, 0, uintptr(targetProc.ProcessID)) // PROCESS_ALL_ACCESS
	if handle == 0 {
		return 0, 0, fmt.Errorf("failed to open process %d", targetProc.ProcessID)
	}
	return targetProc.ProcessID, handle, nil
}
