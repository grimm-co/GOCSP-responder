package main

import (
	"flag"
	_ "fmt"
	"gocsp-responder/responder"
)

func main() {
	resp := responder.Responder()
	flag.StringVar(&resp.IndexFile, "index", resp.IndexFile, "the CA index filename")
	flag.Parse()
	resp.Serve()
}
