package authdb

import (
	"database/sql"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/khaugen7/kerberos-go/internal/encryption"
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

func InitializeDb(path string) *sql.DB {
	dbFile := constructDbPath(path)
	if !utils.FileExists(dbFile) {
		log.Println("Running first time setup...")
		file, err := os.Create(dbFile)
		if err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
	db := SqliteConnect(dbFile)

	createUserTable(db)
	createKeyTable(db)
	insertSharedKeys(db)
	log.Println("Server: Initialization complete.")
	return db
}

func SqliteConnect(path string) *sql.DB {
	dbFile := constructDbPath(path)
	if !utils.FileExists(dbFile) {
		log.Fatal("Database file does not exist")
	}

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
	return db
}

func constructDbPath(path string) string {
	if strings.HasSuffix(path, "kerberos.db") {
		return path
	}
	return filepath.Join(path, "kerberos.db")
}

func createUserTable(db *sql.DB) {
	users_table := `CREATE TABLE IF NOT EXISTS user_auth (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"first_name" TEXT,
		"last_name" TEXT,
        "username" TEXT UNIQUE,
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
}

func createKeyTable(db *sql.DB) {
	keys_table := `CREATE TABLE IF NOT EXISTS keys (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"key_name" TEXT UNIQUE,
		"key" TEXT);`
	query, err := db.Prepare(keys_table)
	if err != nil {
		log.Fatal(err)
	}
	_, err = query.Exec()
	if err != nil {
		log.Fatal(err)
	}
	query.Close()
}

func insertSharedKeys(db *sql.DB) {
	stmt, _ := db.Prepare("INSERT OR IGNORE INTO keys (id, key_name, key) VALUES (?, ?, ?)")
	defer stmt.Close()

	as_tgsKey := hex.EncodeToString(encryption.GenerateRandomBytes(32))
	tgs_fsKey := hex.EncodeToString(encryption.GenerateRandomBytes(32))

	stmt.Exec(nil, "as-tgs", as_tgsKey)
	stmt.Exec(nil, "tgs-fs", tgs_fsKey)
}

func GetSharedKey(keyName string, db *sql.DB) string {
	stmt, _ := db.Prepare("SELECT key FROM keys WHERE key_name = ?")
	defer stmt.Close()

	var key string
	err := stmt.QueryRow(keyName).Scan(&key)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func AddUser(user UserAuth, db *sql.DB) {
	stmt, _ := db.Prepare("INSERT INTO user_auth (id, first_name, last_name, username, key) VALUES (?, ?, ?, ?, ?)")
	defer stmt.Close()
	stmt.Exec(nil, user.FirstName, user.LastName, user.Username, user.Key)

	log.Printf("Added Successfully\nUser: %s %s\nUsername: %s\n", user.FirstName, user.LastName, user.Username)
}

func UpdateUser(idToUpdate int, newInfo UserAuth, db *sql.DB) {
	stmt, _ := db.Prepare("UPDATE user_auth SET first_name = ?, last_name = ?, username = ?, key = ? WHERE id = ?")
	defer stmt.Close()
	stmt.Exec(newInfo.FirstName, newInfo.LastName, newInfo.Username, newInfo.Key, idToUpdate)

	log.Printf("User %s updated successfully", newInfo.Username)
}

func DeleteUser(idToDelete int, username string, db *sql.DB) {
	stmt, _ := db.Prepare("DELETE FROM user_auth WHERE id = ?")
	defer stmt.Close()
	stmt.Exec(idToDelete)

	log.Printf("User %s deleted successfully", username)
}

func FindUserByUsername(username string, db *sql.DB) []UserAuth {
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username, key FROM user_auth WHERE username = ? COLLATE NOCASE")
	defer stmt.Close()
	rows, err := stmt.Query(username)
	if err != nil {
		log.Fatal(err)
	}

	return populateResultSlice(rows)
}

func FindUserByFirstName(name string, db *sql.DB) []UserAuth {
	name = "%" + name + "%"
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username, key FROM user_auth WHERE first_name LIKE ?")
	defer stmt.Close()
	rows, err := stmt.Query(name)
	if err != nil {
		log.Fatal(err)
	}

	return populateResultSlice(rows)
}

func FindUserByLastName(name string, db *sql.DB) []UserAuth {
	name = "%" + name + "%"
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username, key FROM user_auth WHERE last_name LIKE ?")
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
	stmt, _ := db.Prepare("SELECT id, first_name, last_name, username, key FROM user_auth WHERE first_name LIKE ? AND last_name LIKE ?")
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
		err := rows.Scan(&user.Id, &user.FirstName, &user.LastName, &user.Username, &user.Key)
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
