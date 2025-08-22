// build with go build -buildmode=c-shared -o name.dll

package main

// #include <stdint.h>
import "C"

import (
	"github.com/carved4/go-wincall"
)

//export Test
func Test() {
	title, _ := wincall.UTF16ptr("dll remote inject test")
	message, _ := wincall.UTF16ptr("this is a test")
	wincall.Call("user32.dll", "MessageBoxW", 0, title, message, 0x00000002)
}

func main() {}
