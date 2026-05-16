package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"vpn0/vpn"
)

// Generate a new base64 encoded private key.
//
// Unless we can read a private key on stdin,
// in which case we return the public key.
func main() {
	info, err := os.Stdin.Stat()
	if err != nil {
		log.Fatal(err)
	}
	if (info.Mode() & os.ModeCharDevice) == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		k, err := vpn.PubKey(b)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(k)
		return
	}
	k, err := vpn.GenKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(k)
}
