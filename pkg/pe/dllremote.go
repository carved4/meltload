package pe

import "fmt"

// LoadDLLRemote maps a DLL into a remote process and runs TLS/DllMain.
// functionIdentifier optionally is a string export name to invoke after attach.
func LoadDLLRemote(pHandle uintptr, dllBytes []byte, functionIdentifier ...interface{}) (*DLLMapping, error) {
    var exportName string
    if len(functionIdentifier) > 0 {
        if s, ok := functionIdentifier[0].(string); ok {
            exportName = s
        }
    }
	pid, pidErr := GetProcessIdFromHandle(pHandle)
	if pidErr != nil {
		return nil, fmt.Errorf("failed to get PID from handle: %v", pidErr)
	}
	ri, err := newRemoteImage(pHandle, pid, dllBytes)
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
    // Run TLS/DllMain and optional export
    ri.runTLSAndEntry(exportName)
    return createDLLMapping(ri.base, ri.imageSize), nil
}
