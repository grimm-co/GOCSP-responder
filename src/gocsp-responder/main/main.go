package main

import (
	"flag"
	_ "fmt"
	"gocsp-responder/responder"
)

func main() {
	resp := responder.Responder()
	flag.StringVar(&resp.IndexFile, "index", resp.IndexFile, "the CA index filename")
	flag.StringVar(&resp.CaCertFile, "cacert", resp.CaCertFile, "the CA certificate filename")
	flag.StringVar(&resp.RespCertFile, "rcert", resp.RespCertFile, "the responder certificate filename")
	flag.StringVar(&resp.RespKeyFile, "rkey", resp.RespKeyFile, "the responder key filename")
	flag.Parse()
	resp.Serve()
}
