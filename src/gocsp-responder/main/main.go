package main

import (
	"flag"
	_ "fmt"
	"gocsp-responder/responder"
)

func main() {
	resp := responder.Responder()
	flag.StringVar(&resp.IndexFile, "index", resp.IndexFile, "CA index filename")
	flag.StringVar(&resp.CaCertFile, "cacert", resp.CaCertFile, "CA certificate filename")
	flag.StringVar(&resp.RespCertFile, "rcert", resp.RespCertFile, "responder certificate filename")
	flag.StringVar(&resp.RespKeyFile, "rkey", resp.RespKeyFile, "responder key filename")
	flag.StringVar(&resp.Address, "bind", resp.Address, "bind address")
	flag.IntVar(&resp.Port, "port", resp.Port, "listening port")
	flag.BoolVar(&resp.Ssl, "ssl", resp.Ssl, "use SSL")
	flag.Parse()
	resp.Serve()
}
