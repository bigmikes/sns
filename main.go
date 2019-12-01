package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/bigmikes/sns/notary"
	"github.com/bigmikes/sns/server"
)

var errorMessage = `Error: certificate and private key files are required.
`

var (
	port   = flag.String("port", "443", "Listen port")
	addr   = flag.String("addr", "", "Listen IP address")
	cert   = flag.String("crt", "", "Certificate file")
	prvKey = flag.String("key", "", "Private key file")
	ecCert = flag.String("sign", "", "EC certificate to be used for ECDSA signature")
)

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	if *cert == "" || *prvKey == "" {
		fmt.Fprintf(flag.CommandLine.Output(), errorMessage)
		flag.Usage()
		os.Exit(2)
	}

	address := *addr + ":" + *port

	n, err := notary.NewNotary(*ecCert)
	if err != nil {
		log.Fatal(err)
	}

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

	tmpl := template.Must(template.ParseFiles("form.html"))
	s.AddEndpoint("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			tmpl.Execute(w, nil)
		} else {
			payload := r.FormValue("payload")

			sign, err := n.SignPayload([]byte(payload))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			signX := fmt.Sprintf("%x", sign.Signature)

			tmpl.Execute(w, struct {
				Success   bool
				Timestamp string
				Sign      string
			}{
				true,
				sign.Ts,
				signX,
			})
		}
	})
	log.Println("Starting the server...")

	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
	log.Println("Server exited")
}
