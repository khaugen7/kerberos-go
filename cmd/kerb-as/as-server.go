package main

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/khaugen7/kerberos-go/internal/authdb"
	"github.com/khaugen7/kerberos-go/internal/encryption"
	"github.com/khaugen7/kerberos-go/internal/kerb"
)

var sqlDb *sql.DB

func serverMain(host string, port int, db *sql.DB) {
	sqlDb = db
	addr := host + ":" + strconv.Itoa(port)

	http.HandleFunc("/auth", handleAuth)

	log.Printf("Server listening at %s", addr)
	err := http.ListenAndServe(addr, nil)

	if errors.Is(err, http.ErrServerClosed) {
		log.Printf("Server closed.")
	} else if err != nil {
		log.Fatal(err)
	}
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Username")
	if username == "" {
		w.Header().Set("X-Missing-Field", "X-Username")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	foundUsers := authdb.FindUserByUsername(username, sqlDb)
	if len(foundUsers) == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	user := foundUsers[0]
	tgsSessionKey := encryption.GenerateRandomBytes(32)
	valid := time.Now().Add(time.Hour * 1)

	tgt := kerb.Ticket{
		Username:   username,
		SessionKey: tgsSessionKey,
		Validity:   valid,
	}

	userKey, _ := hex.DecodeString(user.Key)

	// Encrypt TGT with shared key between AS and TGS
	asTgsKey, _ := hex.DecodeString(authdb.GetSharedKey("as-tgs", sqlDb))
	encTgt, _ := encryption.Encrypt(asTgsKey, tgt)

	// Encrypt user-TGS session key with user key
	encTgsSessionKey, _ := encryption.Encrypt(userKey, tgsSessionKey)
	keyLen := strconv.Itoa(len(encTgsSessionKey))

	response := append(encTgsSessionKey, encTgt...)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Key-Length", keyLen)

	w.Write(response)
}
