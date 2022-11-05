package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/khaugen7/kerberos-go/internal/authdb"
)

var admin bool
var sqlitePath string
var help bool

var (
	host string
	port int
)

type User struct {
	username, key string
}

func parseFlags() {
	flag.BoolVar(&admin, "admin", false, "Administrator login")
	flag.StringVar(&sqlitePath, "db", "", "Directory for Sqlite db")
	flag.StringVar(&host, "h", "127.0.0.1", "Server host")
	flag.IntVar(&port, "p", 8555, "Server port")
	flag.BoolVar(&help, "help", false, "Display help")
	flag.Parse()
}

func main() {
	parseFlags()

	if help {
		displayHelp()
	}

	db := authdb.InitializeDb(sqlitePath)
	defer db.Close()

	if admin {
		adminMain(db)
	} else {
		serverMain(host, port, db)
	}
}

func displayHelp() {
	fmt.Println("\nUsage: kerb-as [-admin] [-db PATH] [-h HOST] [-p PORT] [-help]")
	flag.PrintDefaults()
	os.Exit(0)
}