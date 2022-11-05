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
var help bool

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
	flag.StringVar(&asHost, "ash", "127.0.0.1", "Authentication server host")
	flag.IntVar(&asPort, "asp", 8555, "Authentication server port")
	flag.StringVar(&tgsHost, "tgsh", "127.0.0.1", "Ticket granting server host")
	flag.IntVar(&tgsPort, "tgsp", 8655, "Ticket granting server port")
	flag.StringVar(&fsHost, "fsh", "127.0.0.1", "File server host")
	flag.IntVar(&fsPort, "fsp", 8755, "File server port")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.BoolVar(&help, "help", false, "Display help")
	flag.Parse()
}

func main() {
	parseFlags()

	if help {
		displayHelp()
		os.Exit(0)
	}

	if len(flag.Args()) == 0 {
		log.Println("Missing requested filename!")
		displayHelp()
		os.Exit(1)
	}

	reqFile := flag.Arg(0)
	asAddr, tgsAddr, fsAddr := buildUrls()

	fmt.Println("Welcome to my Kerberos Authentication demo!")

	u, p, _ := utils.Credentials()

	logVerbose("Requesting authentication for user " + u + " with Kerberos authentication server")
	encTgsSessionKey, tgt := requestAuthorization(u, asAddr)
	logVerbose("Success!")

	userKey := encryption.DeriveSecretKey(u, p)

	var tgsSessionKey []byte
	err := encryption.Decrypt(userKey, encTgsSessionKey, &tgsSessionKey)
	if err != nil {
		log.Fatal("Invalid Password")
	}

	tgsAuth := generateAuth(u)
	encTgsAuth, _ := encryption.Encrypt(tgsSessionKey, tgsAuth)

	logVerbose("Requesting service ticket from ticket granting server")
	encFsSessionKey, st := requestServiceTicket(encTgsAuth, tgt, tgsAddr)
	logVerbose("Success!")

	var fsSessionKey []byte
	encryption.Decrypt(tgsSessionKey, encFsSessionKey, &fsSessionKey)

	fsAuth := generateAuth(u)
	encFsAuth, _ := encryption.Encrypt(fsSessionKey, fsAuth)

	logVerbose("Requesting file for download from file server")
	file := requestFile(encFsAuth, st, reqFile, fsAddr)
	fmt.Printf("Successfully authenticated via the Kerberos protocol and retrieved file %s", file)
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

func requestFile(auth []byte, encTicket []byte, reqFile string, fsAddr string) string {
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
	return filename
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

func displayHelp() {
	fmt.Println("\nUsage: kerb-client [-ash HOST] [-asp PORT] [-ash HOST] [-asp PORT] [-ash HOST] [-asp PORT] [-v verbose] [-help] filename")
	flag.PrintDefaults()
	fmt.Println("filename string\n\tFilename to request from the server")
}