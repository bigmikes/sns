package main

import (
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/bigmikes/sns/server"
)

var errorMessage = `Error: certificate and private key files are required.
`

var (
	port   = flag.String("port", "443", "Listen port")
	addr   = flag.String("addr", "", "Listen IP address")
	cert   = flag.String("crt", "", "Certificate file")
	prvKey = flag.String("key", "", "Private key file")
)

func main() {
	flag.Parse()

	if *cert == "" || *prvKey == "" {
		fmt.Fprintf(flag.CommandLine.Output(), errorMessage)
		flag.Usage()
		os.Exit(2)
	}

	address := *addr + ":" + *port

	log.SetFlags(log.Lshortfile)
	s := server.NewHTTPSServer(
		address,
		*prvKey,
		*cert,
		&tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		},
	)
	s.AddEndpoint("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is an example.\n"))
	})

	tmpl := template.Must(template.ParseFiles("form.html"))
	s.AddEndpoint("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			tmpl.Execute(w, nil)
		} else {
			payload := r.FormValue("payload")
			sha := sha256.Sum256([]byte(payload))
			result := fmt.Sprintf("%x", sha)
			tmpl.Execute(w, struct {
				Success bool
				Result  string
			}{
				true,
				result,
			})
		}
	})
	log.Println("Starting the server...")
	err := s.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Server exited")
}
