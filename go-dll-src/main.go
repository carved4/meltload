// build with go build -buildmode=c-shared -o name.dll

package main

// #include <stdint.h>
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

//export HostInfo
func HostInfo() {
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	fmt.Println("go dll example")
	fmt.Printf("Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Hostname: %s\n", host)
	fmt.Printf("User: %s\n", user)
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("CPU Count: %d\n", runtime.NumCPU())
	fmt.Printf("Go Version: %s\n", runtime.Version())
}

func main() {}
