package main

import (
	"app/fuckhttp"
	"net/http"
)

func main() {
	h := fuckhttp.NewServeMux()
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test demo"))
	})
	fuckhttp.ListenAndServe("0.0.0.0:8000", h, 20)

}
