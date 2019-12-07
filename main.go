package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/bigmikes/sns/notary"
	"github.com/bigmikes/sns/server"
	"github.com/bigmikes/sns/storage"
)

var errorMessage = `Error: certificate and private key files are required.
`

var (
	port       = flag.String("port", "443", "Listen port")
	addr       = flag.String("addr", "", "Listen IP address")
	cert       = flag.String("crt", "", "Certificate file")
	prvKey     = flag.String("key", "", "Private key file")
	ecCert     = flag.String("sign", "", "EC certificate to be used for ECDSA signature")
	signFolder = flag.String("dir", "", "Directory where signatures will be stored")
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

	notSrv, err := notary.NewNotary(*ecCert)
	if err != nil {
		log.Fatal(err)
	}

	storSrv := storage.NewFileStorage(*signFolder)

	s.AddEndpoint("/sign", signHandler(notSrv, storSrv))
	s.AddEndpoint("/list", listHandler(storSrv))
	s.AddEndpoint("/view", viewHandler(storSrv))

	log.Println("Starting the server...")
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
	log.Println("Server exited")
}

func signHandler(n *notary.Notary, s storage.Storage) server.HandlerFunc {
	tmpl := template.Must(template.ParseFiles("sign.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl.Execute(w, nil)
		} else if r.Method == http.MethodPost {
			payload := r.FormValue("payload")
			sign, err := n.SignPayload([]byte(payload))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			body, err := sign.MarshalJSON()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			hash := hex.EncodeToString(sign.Hash)
			err = s.Store(storage.StorageEntry{
				Title: hash + ".json",
				Body:  body,
			})
			if err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			http.Redirect(w, r, "/view?hash="+hash, http.StatusFound)
		} else {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	}
}

func listHandler(s storage.Storage) server.HandlerFunc {
	tmpl := template.Must(template.ParseFiles("list.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			entries, err := s.List()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			jsonEntries := make([]notary.SignedPayloadJSON, 0, len(entries))
			for _, entry := range entries {
				json, err := notary.UnmarshalJSON(entry.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				jsonEntries = append(jsonEntries, json)
			}
			render := struct {
				Entries []notary.SignedPayloadJSON
			}{
				jsonEntries,
			}
			tmpl.Execute(w, render)
		} else {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	}
}

func viewHandler(s storage.Storage) server.HandlerFunc {
	tmpl := template.Must(template.ParseFiles("view.html"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			hash := r.URL.Query().Get("hash")
			entry, err := s.Load(hash + ".json")
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
			}
			json, err := notary.UnmarshalJSON(entry.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			tmpl.Execute(w, json)
		} else {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	}
}
