package main

import (
	"flag"

	"github.com/khaugen7/kerberos-go/internal/authdb"
)

var admin bool

type User struct {
	username, key string
}

func parseFlags() {
	flag.BoolVar(&admin, "a", false, "Administrator login")
	flag.Parse()
}

func main() {
	authdb.InitializeDb()
	parseFlags()

	if admin {
		adminMain()
	} else {
		serverMain()
	}
}
