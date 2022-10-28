package main

import (
	"bufio"
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

var adminMenu *wmenu.Menu

func adminMain() {
	username, password, _ := credentials()
	if username == "admin" && password == "admin" {

		fmt.Println("\n\nADMINISTRATOR MENU")
		adminMenu = wmenu.NewMenu("What would you like to do?")

		adminMenu.Action(func(opts []wmenu.Opt) error { handleFunc(opts); return nil })

		adminMenu.Option("Add a new User", 0, false, nil)
		adminMenu.Option("Find a User", 1, false, nil)
		adminMenu.Option("Delete a person by ID", 2, false, nil)
		adminMenu.Option("Quit", 3, false, nil)
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

func handleFunc(opts []wmenu.Opt) {

	switch opts[0].Value {

	case 0:
		fmt.Println("Adding a new user")
	case 1:
		fmt.Println("Finding a user")
	case 2:
		fmt.Println("Update a user's information")
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
