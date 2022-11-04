package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/khaugen7/kerberos-go/internal/encryption"
	"github.com/khaugen7/kerberos-go/internal/kerb"
	"github.com/khaugen7/kerberos-go/internal/utils"
)

var verbose bool

var (
	asHost  string
	tgsHost string
	fsHost  string
)

var (
	asPort  int
	tgsPort int
	fsPort  int
)

func parseFlags() {
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.StringVar(&asHost, "ash", "127.0.0.1", "Authentication server host")
	flag.IntVar(&asPort, "asp", 8555, "Authentication server port")
	flag.StringVar(&tgsHost, "tgsh", "127.0.0.1", "Ticket granting server host")
	flag.IntVar(&tgsPort, "tgsp", 8655, "Ticket granting server port")
	flag.StringVar(&fsHost, "fsh", "127.0.0.1", "File server host")
	flag.IntVar(&fsPort, "fsp", 8755, "File server port")
	flag.Parse()
}

func main() {
	parseFlags()
	if len(flag.Args()) == 0 {
		log.Fatalf("Missing requested filename!")
	}

	reqFile := flag.Arg(0)
	asAddr, tgsAddr, fsAddr := buildUrls()

	fmt.Println("Welcome to my Kerberos Authentication demo!")
	fmt.Print("If you would like step-by-step explanations about how Kerberos works, please run the client with the -v (verbose) flag.\n\n")

	logVerbose("Kerberos has four main components (at least it does in my simplified demo):\n")
	logVerbose("1. Client that requests a resource or service (that's this program!)\n")
	logVerbose("2. Authentication server (AS) that maintains a database of pre-shared user credentials and provides the user with a ticket-granting ticket\n")
	logVerbose("3. Ticket granting server (TGS) that validates the ticket granting ticket from the AS and provides a service ticket to a validated user\n")
	logVerbose("4. File server (FS) that validates the service ticket and provides the requested resource to the user\n\n")

	logVerbose("The first step is typing your credentials. These will be the same pre-shared credentials that reside in the authentication database.\n")
	u, p, _ := utils.Credentials()

	encTgsSessionKey, tgt := requestAuthorization(u, asAddr)

	userKey := encryption.DeriveSecretKey(u, p)

	var tgsSessionKey []byte
	err := encryption.Decrypt(userKey, encTgsSessionKey, &tgsSessionKey)
	if err != nil {
		log.Fatal("Invalid Password")
	}

	tgsAuth := generateAuth(u)
	encTgsAuth, _ := encryption.Encrypt(tgsSessionKey, tgsAuth)

	encFsSessionKey, st := requestServiceTicket(encTgsAuth, tgt, tgsAddr)

	var fsSessionKey []byte
	encryption.Decrypt(tgsSessionKey, encFsSessionKey, &fsSessionKey)

	fsAuth := generateAuth(u)
	encFsAuth, _ := encryption.Encrypt(fsSessionKey, fsAuth)

	requestFile(encFsAuth, st, reqFile, fsAddr)
}

func requestAuthorization(username, asAddr string) ([]byte, []byte) {
	c := http.Client{
		Timeout: time.Duration(5) * time.Second,
	}
	req, err := http.NewRequest("GET", asAddr + "/auth", nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Username", username)

	resp, err := c.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatalf("Authentication Server: HTTP request failed with status code %d", resp.StatusCode)
	}

	keyLen, _ := strconv.Atoi(resp.Header.Get("X-Key-Length"))
	body, _ := ioutil.ReadAll(resp.Body)

	return body[:keyLen], body[keyLen:]
}

func requestServiceTicket(auth []byte, encTicket []byte, tgsAddr string) ([]byte, []byte) {
	c := http.Client{
		Timeout: time.Duration(5) * time.Second,
	}

	body := append(encTicket, auth...)

	req, err := http.NewRequest("GET", tgsAddr + "/ticket", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Ticket-Length", strconv.Itoa(len(encTicket)))

	resp, err := c.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatalf("Ticket Granting Server: HTTP request failed with status code %d", resp.StatusCode)
	}

	keyLen, _ := strconv.Atoi(resp.Header.Get("X-Key-Length"))
	resBody, _ := ioutil.ReadAll(resp.Body)

	return resBody[:keyLen], resBody[keyLen:]
}

func requestFile(auth []byte, encTicket []byte, reqFile string, fsAddr string) {
	c := http.Client{
		Timeout: time.Duration(5) * time.Second,
	}

	body := append(encTicket, auth...)

	req, err := http.NewRequest("GET", fsAddr + "/download/" + reqFile, bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Ticket-Length", strconv.Itoa(len(encTicket)))

	resp, err := c.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		log.Fatalf("File Server: HTTP request failed with status code %d", resp.StatusCode)
	}

	_, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	filename := params["filename"]
	
	resBody, _ := ioutil.ReadAll(resp.Body)

	file, err := os.Create("./" + filename)
	if err != nil {
		log.Fatal(err)
	}

	file.Write(resBody)
}

func generateAuth(username string) kerb.Autheticator {
	return kerb.Autheticator {
		Username: username,
		Timestamp: time.Now(),
	}
}

func buildUrls() (string, string, string) {
	asAddr := "http://" + asHost + ":" + strconv.Itoa(asPort)
	tgsAddr := "http://" + tgsHost + ":" + strconv.Itoa(tgsPort)
	fsAddr := "http://" + fsHost + ":" + strconv.Itoa(fsPort)

	return asAddr, tgsAddr, fsAddr
}

func logVerbose(msg string) {
	if verbose {
		fmt.Println(msg)
	}
}
