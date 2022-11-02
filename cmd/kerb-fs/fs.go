package main

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/khaugen7/kerberos-go/internal/authdb"
	"github.com/khaugen7/kerberos-go/internal/encryption"
	"github.com/khaugen7/kerberos-go/internal/kerb"
	"github.com/khaugen7/kerberos-go/internal/utils"
)

var sqlitePath string
var db *sql.DB

var (
	host string
	port int
)

func parseFlags() {
	flag.StringVar(&sqlitePath, "d", "", "Directory for Sqlite db")
	flag.StringVar(&host, "h", "127.0.0.1", "Server host")
	flag.IntVar(&port, "p", 8755, "Server port")
	flag.Parse()
}

func main() {
	parseFlags()
	addr := host + ":" + strconv.Itoa(port)
	db = authdb.SqliteConnect(sqlitePath)

	http.HandleFunc("/download/", handleDownload)

	log.Printf("Server listening at %s", addr)
	err := http.ListenAndServe(addr, nil)

	if errors.Is(err, http.ErrServerClosed) {
		log.Printf("Server closed.")
	} else if err != nil {
		log.Fatal(err)
	}
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	tickLen, _ := strconv.Atoi(r.Header.Get("X-Ticket-Length"))
	if tickLen == 0 {
		w.Header().Set("X-Missing-Field", "X-Ticket-Length")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	content, _ := ioutil.ReadAll(r.Body)
	encTicket, encAuth := content[:tickLen], content[tickLen:]

	var ticket kerb.Ticket
	var auth kerb.Autheticator

	tgsFsKey, _ := hex.DecodeString(authdb.GetSharedKey("tgs-fs", db))

	err := encryption.Decrypt(tgsFsKey, encTicket, &ticket)
	if err != nil {
		log.Fatal("Failed to decrypt ticket")
	}

	clientSessionKey := ticket.SessionKey

	err = encryption.Decrypt(clientSessionKey, encAuth, &auth)
	if err != nil {
		log.Fatal("Failed to decrypt client authenticator")
	}

	if !kerb.ValidateClient(auth, ticket) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	filePath := strings.Split(r.URL.Path, "/download/")
	reqFile := filePath[len(filePath)-1]

	if !utils.FileExists(reqFile) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	b, err := ioutil.ReadFile(reqFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; " + filepath.Base(reqFile))
	w.Write(b)
}



