package authdb

import (
	"database/sql"
	"log"
	"os"

	"github.com/khaugen7/kerberos-go/internal/utils"
)

type UserAuth struct {
	Id        int
	FirstName string
	LastName  string
	Username  string
	Key       string
}

func InitializeDb() {
	if !utils.FileExists("kerberos.db") {
		firstTimeSetup()
	}
}

func firstTimeSetup() {
	log.Println("Running first time setup...")

	file, err := os.Create("kerberos.db")
	if err != nil {
		log.Fatal(err)
	}
	file.Close()
}

func createUserTable(db *sql.DB) {
	users_table := `CREATE TABLE user_auth (
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
	log.Println("Table created successfully!")
}

func addUserAuth(user UserAuth, db *sql.DB) {
	stmt, _ := db.Prepare("INSERT INTO user_auth (id, first_name, last_name, username, key) VALUES (?, ?, ?, ?, ?)")
	stmt.Exec(nil, user.FirstName, user.LastName, user.Username, user.Key)
	defer stmt.Close()

	log.Printf("Added User %s %s with username %s\n", user.FirstName, user.LastName, user.Username)
}
