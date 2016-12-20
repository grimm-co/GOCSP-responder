package main

import (
	"encoding/hex"
	"fmt"
	"gocsp-responder/server"
	"golang.org/x/crypto/ocsp"
)

func main() {
	s, _ := hex.DecodeString("30423040303e303c303a300906052b0e03021a05000414738446ebf462bb192ce62d5cfdc1dc699c28cfe404141140dcd8c7210a0381d1c2f9b76c2610f5d2fe65020113")
	r, _ := ocsp.ParseRequest([]byte(s))
	fmt.Printf("%s", r.SerialNumber)
	server.Serve("", 8888)
}
