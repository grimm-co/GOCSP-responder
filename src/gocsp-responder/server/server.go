package server

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	//if r.Header.Get("Content-Type") != "application/ocsp-request" {
	//	fmt.Println(r.Header.Get("Content-Type"))
	//}
	var b []byte
	switch r.Method {
	case "POST":
		r.Body.Read(b)
	case "GET":
		b, _ = base64.StdEncoding.DecodeString(r.URL.Path[1:])
	default:
		fmt.Println("Unsupported request method")
		return
	}
	status, _ := verify(b)
}

//takes the der encoded ocsp request and verifies it
func verify(req []byte) (bool, error) {
	preq, err := ocsp.ParseRequest(req)
	return true, err
}

func Serve(addr string, port int) {
	http.HandleFunc("/", handler)
	http.ListenAndServe(fmt.Sprintf("%s:%d", addr, port), nil)
}
