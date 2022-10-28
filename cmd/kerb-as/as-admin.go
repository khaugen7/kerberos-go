package main

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/dixonwille/wmenu"
	"github.com/khaugen7/kerberos-go/internal/authdb"
	"github.com/khaugen7/kerberos-go/internal/encryption"
	"golang.org/x/term"
)

var adminMenu, findMenu *wmenu.Menu

func adminMain(db *sql.DB) {
	username, password, _ := credentials()
	if username == "admin" && password == "admin" {

		fmt.Println("\n\nADMINISTRATOR MENU")
		adminMenu = wmenu.NewMenu("What would you like to do?")

		adminMenu.Action(func(opts []wmenu.Opt) error { handleFunc(db, opts); return nil })

		adminMenu.Option("Add a new User", 0, false, nil)
		adminMenu.Option("Find a user", 1, false, nil)
		adminMenu.Option("Update user information", 2, false, nil)
		adminMenu.Option("Delete a person by ID", 3, false, nil)
		adminMenu.Option("Quit", 4, false, nil)
		menuerr := adminMenu.Run()

		if menuerr != nil {
			log.Fatal(menuerr)
		}
	} else {
		log.Fatal("Invalid administrator credentials")
	}
}

func credentials() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Administrator Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	fmt.Print("Enter Administrator Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(username), password, nil
}

func handleFunc(db *sql.DB, opts []wmenu.Opt) {

	switch opts[0].Value {

	case 0:
		fmt.Println("Adding a new user")
		newUser := gatherUserInfo()
		authdb.AddUser(newUser, db)
	case 1:
		fmt.Println("Finding users")
		findUser(db)
	case 2:
		fmt.Println("Updating user information")
	case 3:
		fmt.Println("Deleting a user by ID")
	case 4:
		fmt.Println("Quitting application")
	default:
		fmt.Println("Please select an option. '4' to quit.")
		adminMenu.Run()
	}
}

func gatherUserInfo() authdb.UserAuth {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Enter first name of user: ")
	firstName, _ := reader.ReadString('\n')
	firstName = strings.TrimSpace(firstName)

	fmt.Println("Enter last name of user: ")
	lastName, _ := reader.ReadString('\n')
	lastName = strings.TrimSpace(lastName)

	fmt.Println("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Println("Enter password: ")
	password, _ := reader.ReadString('\n')

	key := encryption.DeriveSecretKey(username, password)
	stringKey := hex.EncodeToString(key)

	return authdb.UserAuth{
		FirstName: firstName,
		LastName:  lastName,
		Username:  username,
		Key:       stringKey,
	}
}

func findUser(db *sql.DB) {
	findMenu = wmenu.NewMenu("What would you like to do?")

	findMenu.Action(func(opts []wmenu.Opt) error { findFunc(db, opts); return nil })

	findMenu.Option("Find user by username", 0, false, nil)
	findMenu.Option("Find user by first name", 1, false, nil)
	findMenu.Option("Find user by last name", 2, false, nil)
	findMenu.Option("Find user by first and last name", 3, false, nil)
	findMenu.Option("Quit", 4, false, nil)
	menuerr := findMenu.Run()

	if menuerr != nil {
		log.Fatal(menuerr)
	}
}

func findFunc(db *sql.DB, opts []wmenu.Opt) {
	reader := bufio.NewReader(os.Stdin)
	var results []authdb.UserAuth
	switch opts[0].Value {

	case 0:
		fmt.Println("Enter username: ")
		username, _ := reader.ReadString('\n')
		username = strings.TrimSpace(username)
		results = authdb.FindUserByUsername(username, db)

	case 1:
		fmt.Println("Enter first name: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)
		results = authdb.FindUserByFirstName(name, db)

	case 2:
		fmt.Println("Enter last name: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)
		results = authdb.FindUserByLastName(name, db)

	case 3:
		fmt.Println("Enter first and last name: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)
		results = authdb.FindUserByFirstAndLastName(name, db)

	case 4:
		fmt.Println("Quitting application")
		os.Exit(0)
	default:
		fmt.Println("Please select an option. '4' to quit.")
		findMenu.Run()
	}

	if results == nil {
		findMenu.Run()
	}

	log.Printf("Found %d results\n", len(results))

	for _, user := range results {
		log.Printf("{id: %d, first_name: %s, last_name: %s, username: %s}", user.Id, user.FirstName, user.LastName, user.Username)
	}
}
