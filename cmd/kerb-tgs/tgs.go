package main

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/khaugen7/kerberos-go/internal/authdb"
	"github.com/khaugen7/kerberos-go/internal/encryption"
	"github.com/khaugen7/kerberos-go/internal/kerb"
)

var sqlitePath string
var db *sql.DB

var (
	host string
	port int
)

func parseFlags() {
	flag.StringVar(&sqlitePath, "db", "", "Directory for Sqlite db")
	flag.StringVar(&host, "h", "127.0.0.1", "Server host")
	flag.IntVar(&port, "p", 8655, "Server port")
	flag.Parse()
}

func main() {
	parseFlags()
	addr := host + ":" + strconv.Itoa(port)
	db = authdb.SqliteConnect(sqlitePath)

	http.HandleFunc("/ticket", handleTicket)

	log.Printf("Server listening at %s", addr)
	err := http.ListenAndServe(addr, nil)

	if errors.Is(err, http.ErrServerClosed) {
		log.Printf("Server closed.")
	} else if err != nil {
		log.Fatal(err)
	}
}

func handleTicket(w http.ResponseWriter, r *http.Request) {
	tickLen, _ := strconv.Atoi(r.Header.Get("X-Ticket-Length"))
	if tickLen == 0 {
		w.Header().Set("X-Missing-Field", "X-Ticket-Length")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	content, _ := ioutil.ReadAll(r.Body)
	encTicket, encAuth := content[:tickLen], content[tickLen:]

	asTgsKey, _ := hex.DecodeString(authdb.GetSharedKey("as-tgs", db))

	var ticket kerb.Ticket
	err := encryption.Decrypt(asTgsKey, encTicket, &ticket)
	if err != nil {
		log.Fatal("Failed to decrypt ticket")
	}

	clientSessionKey := ticket.SessionKey

	var auth kerb.Autheticator
	err = encryption.Decrypt(clientSessionKey, encAuth, &auth)
	if err != nil {
		log.Fatal("Failed to decrypt client authenticator")
	}

	if !kerb.ValidateClient(auth, ticket) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	serviceTicket := kerb.GenerateTicket(auth.Username)

	// Encrypt Service Ticket with shared key between TGS and FS
	tgsFsKey, _ := hex.DecodeString(authdb.GetSharedKey("tgs-fs", db))
	encServiceTicket, _ := encryption.Encrypt(tgsFsKey, serviceTicket)

	// Encrypt client-FS session key with client-TGS session key
	encFsSessionKey, _ := encryption.Encrypt(clientSessionKey, serviceTicket.SessionKey)
	keyLen := strconv.Itoa(len(encFsSessionKey))

	response := append(encFsSessionKey, encServiceTicket...)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Key-Length", keyLen)

	w.Write(response)
}