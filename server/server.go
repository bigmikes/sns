package server

import (
	"crypto/tls"
	"net/http"
)

type HandlerFunc func(http.ResponseWriter, *http.Request)

type HTTPSServer struct {
	address         string
	privKey, pubKey string
	mux             *http.ServeMux
	tlsConf         *tls.Config
}

func NewHTTPSServer(address, privKey, pubKey string, t *tls.Config) *HTTPSServer {
	return &HTTPSServer{
		address: address,
		privKey: privKey,
		pubKey:  pubKey,
		mux:     http.NewServeMux(),
		tlsConf: t,
	}
}

func (h *HTTPSServer) AddEndpoint(endpoint string, f HandlerFunc) {
	h.mux.HandleFunc(endpoint, f)
}

func (h *HTTPSServer) Start() error {
	srv := &http.Server{
		Addr:         h.address,
		Handler:      h.mux,
		TLSConfig:    h.tlsConf,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	return srv.ListenAndServeTLS(h.pubKey, h.privKey)
}
