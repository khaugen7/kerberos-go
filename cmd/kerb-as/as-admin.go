package main

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dixonwille/wmenu"
	"github.com/khaugen7/kerberos-go/internal/authdb"
	"github.com/khaugen7/kerberos-go/internal/encryption"
	"github.com/khaugen7/kerberos-go/internal/utils"
)

var adminMenu, findMenu *wmenu.Menu

func adminMain(db *sql.DB) {
	fmt.Println("Enter Administrator credentials")
	username, password, _ := utils.Credentials()
	if username == "admin" && password == "admin" {

		adminMenu = wmenu.NewMenu("What would you like to do?")
		adminMenu.Action(func(opts []wmenu.Opt) error { handleFunc(db, opts); return nil })
		adminMenu.Option("Add a new User", 0, false, nil)
		adminMenu.Option("Find a user", 1, false, nil)
		adminMenu.Option("Update user information", 2, false, nil)
		adminMenu.Option("Delete a user", 3, false, nil)
		adminMenu.Option("Quit", 4, false, nil)

		runAdminMenu()

	} else {
		log.Fatal("Invalid administrator credentials")
	}
}

func runAdminMenu() {
	for true {
		fmt.Println("\n\nADMINISTRATOR MENU")
		menuerr := adminMenu.Run()
		if menuerr != nil {
			log.Fatal(menuerr)
		}
	}
}

func handleFunc(db *sql.DB, opts []wmenu.Opt) {

	switch opts[0].Value {

	case 0:
		fmt.Println("\nADDING USER")
		newUser := gatherUserInfo()
		authdb.AddUser(newUser, db)
	case 1:
		fmt.Println("\nFINDING USERS")
		findUser(db)
	case 2:
		fmt.Println("\nUPDATING USER INFORMATION")
		updateUserInfo(db)
	case 3:
		fmt.Println("\nDELETING USER")
		deleteUser(db)
	case 4:
		fmt.Println("\nQuitting application.")
		os.Exit(0)
	default:
		fmt.Println("\nPlease select an option. '4' to quit.")
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
	password = strings.TrimSpace(password)

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

func updateUserInfo(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Enter username of user you wish to update: ")
	currentUser := getUserByUsername(reader, db)
	updatedUser := currentUser

	fmt.Println("Enter updated information. Leave any field empty to keep it the same.")

	fmt.Printf("\nCurrent first name: %s\nNew first name: ", currentUser.FirstName)
	firstName, _ := reader.ReadString('\n')
	firstName = strings.TrimSpace(firstName)
	if firstName != "" {
		updatedUser.FirstName = firstName
	}

	fmt.Printf("\nCurrent last name: %s\nNew last name: ", currentUser.LastName)
	lastName, _ := reader.ReadString('\n')
	lastName = strings.TrimSpace(lastName)
	if lastName != "" {
		updatedUser.LastName = lastName
	}

	fmt.Printf("\nCurrent username: %s\nNew username: ", currentUser.Username)
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username != "" {
		updatedUser.Username = username
	}

	fmt.Println("\nEnter new password (leave empty to keep the same): ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != "" {
		key := encryption.DeriveSecretKey(username, password)
		updatedUser.Key = hex.EncodeToString(key)
	}

	authdb.UpdateUser(currentUser.Id, updatedUser, db)
}

func deleteUser(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Enter username of user you wish to delete: ")
	user := getUserByUsername(reader, db)
	fmt.Printf("Deleting user: {id: %d, first_name: %s, last_name: %s, username: %s}\nAre you sure you wish to proceed? y/n: ",
		user.Id, user.FirstName, user.LastName, user.Username)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	if confirm == "y" || confirm == "yes" {
		authdb.DeleteUser(user.Id, user.Username, db)
	} else {
		fmt.Printf("User %s was not deleted.", user.Username)
	}
}

func getUserByUsername(reader *bufio.Reader, db *sql.DB) authdb.UserAuth {
	currentUsername, _ := reader.ReadString('\n')
	currentUsername = strings.TrimSpace(currentUsername)
	currentUserSlice := authdb.FindUserByUsername(currentUsername, db)
	if len(currentUserSlice) == 0 {
		log.Println("No users found for that username.")
		os.Exit(0)
	}
	return currentUserSlice[0]
}
