package authdb

import (
	"database/sql"
	"log"
	"os"
	"strings"

	"github.com/khaugen7/kerberos-go/internal/utils"
	_ "github.com/mattn/go-sqlite3"
)

type UserAuth struct {
	Id        int
	FirstName string
	LastName  string
	Username  string
	Key       string
}

func InitializeDb() *sql.DB {
	if !utils.FileExists("kerberos.db") {
		log.Println("Running first time setup...")
		file, err := os.Create("kerberos.db")
		if err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
	db, err := sql.Open("sqlite3", "kerberos.db")
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
	createUserTable(db)
	return db
}

func createUserTable(db *sql.DB) {
	users_table := `CREATE TABLE IF NOT EXISTS user_auth (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"first_name" TEXT,
		"last_name" TEXT,
        "username" TEXT,
        "key" TEXT);`
	query, err := db.Prepare(users_table)
	if err != nil {
		log.Fatal(err)
	}
	_, err = query.Exec()
	if err != nil {
		log.Fatal(err)
	}
	query.Close()
	log.Println("Authentication Server: Initialization complete.")
}

func AddUser(user UserAuth, db *sql.DB) {
	stmt, _ := db.Prepare("INSERT INTO user_auth (id, first_name, last_name, username, key) VALUES (?, ?, ?, ?, ?)")
	defer stmt.Close()
	stmt.Exec(nil, user.FirstName, user.LastName, user.Username, user.Key)

	log.Printf("Added Successfully\nUser: %s %s\nUsername: %s\n", user.FirstName, user.LastName, user.Username)
}

func FindUserByUsername(username string, db *sql.DB) []UserAuth {
	username = "%" + username + "%"
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username FROM user_auth WHERE username LIKE ?")
	defer stmt.Close()
	rows, err := stmt.Query(username)
	if err != nil {
		log.Fatal(err)
	}

	return populateResultSlice(rows)
}

func FindUserByFirstName(name string, db *sql.DB) []UserAuth {
	name = "%" + name + "%"
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username FROM user_auth WHERE first_name LIKE ?")
	defer stmt.Close()
	rows, err := stmt.Query(name)
	if err != nil {
		log.Fatal(err)
	}

	return populateResultSlice(rows)
}

func FindUserByLastName(name string, db *sql.DB) []UserAuth {
	name = "%" + name + "%"
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username FROM user_auth WHERE last_name LIKE ?")
	defer stmt.Close()
	rows, err := stmt.Query(name)
	if err != nil {
		log.Fatal(err)
	}

	return populateResultSlice(rows)
}

func FindUserByFirstAndLastName(name string, db *sql.DB) []UserAuth {
	names := strings.Split(name, " ")
	if len(names) != 2 {
		log.Print("Invalid name, please type first and last name separated by a space")
		return nil
	}
	first := "%" + names[0] + "%"
	last := "%" + names[1] + "%"
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username FROM user_auth WHERE first_name LIKE ? AND last_name LIKE ?")
	defer stmt.Close()
	rows, err := stmt.Query(first, last)
	if err != nil {
		log.Fatal(err)
	}

	return populateResultSlice(rows)
}

func populateResultSlice(rows *sql.Rows) []UserAuth {
	defer rows.Close()
	users := make([]UserAuth, 0)

	for rows.Next() {
		user := UserAuth{}
		err := rows.Scan(&user.Id, &user.FirstName, &user.LastName, &user.Username)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, user)
	}
	err := rows.Err()
	if err != nil {
		log.Fatal(err)
	}

	return users
}
