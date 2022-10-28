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
	flag.BoolVar(&admin, "admin", false, "Administrator login")
	flag.Parse()
}

func main() {
	db := authdb.InitializeDb()
	defer db.Close()
	parseFlags()

	if admin {
		adminMain(db)
	} else {
		serverMain()
	}
}
