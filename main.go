package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	hashingAndShit "github.com/supersiem/st-theme-store/helpers"
	_ "modernc.org/sqlite"
)

// types that represent database entities
type Theme struct {
	ID     int
	Theme  string
	UserID sql.NullInt64 // foreign key to User.ID, can be null
}

type User struct {
	ID           int
	Username     string
	Email        string
	PasswordHash string
}

// database stuff
func initDB() *sql.DB {
	db, err := sql.Open("sqlite", "studytools.db")
	if err != nil {
		panic("error opening database")
	}
	return db
}
func makeDBTables(db *sql.DB) {
	// enable foreign key support in SQLite
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		panic(fmt.Sprintf("failed to enable foreign keys: %v", err))
	}

	// create user table
	userTable := `
	CREATE TABLE IF NOT EXISTS user (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL
	);`
	if _, err := db.Exec(userTable); err != nil {
		panic(fmt.Sprintf("failed to create user table: %v", err))
	}

	// create bearer table
	bearerTable := `
	CREATE TABLE IF NOT EXISTS bearer (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token TEXT NOT NULL,
		user_id INTEGER,
		expiry DATETIME NOT NULL,
		FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
	);`
	if _, err := db.Exec(bearerTable); err != nil {
		panic(fmt.Sprintf("failed to create user table: %v", err))
	}

	// create theme table with a foreign key to user(id)
	themeTable := `
	CREATE TABLE IF NOT EXISTS theme (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		theme TEXT NOT NULL,
		user_id INTEGER,
		FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
	);`
	if _, err := db.Exec(themeTable); err != nil {
		panic(fmt.Sprintf("failed to create theme table: %v", err))
	}
}
func makeTheme(theme Theme, db *sql.DB) error {
	query := `INSERT INTO theme (theme, user_id) VALUES (?, ?);`
	_, err := db.Exec(query, theme.Theme, theme.UserID)
	return err
}
func bearerTokenValid(token string, db *sql.DB) (bool, error) {
	query := `SELECT COUNT(*) FROM bearer WHERE token = ? AND expiry > DATETIME('now');`
	row := db.QueryRow(query, token)

	var count int
	err := row.Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// vibe coded
func getLastfewThemes(limit int, skip int, db *sql.DB) ([]Theme, error) {
	query := `SELECT id, theme, user_id FROM theme ORDER BY id DESC LIMIT ? OFFSET ?;`
	rows, err := db.Query(query, limit, skip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	themes := []Theme{}
	for rows.Next() {
		var t Theme
		err := rows.Scan(&t.ID, &t.Theme, &t.UserID)
		if err != nil {
			return nil, err
		}
		themes = append(themes, t)
	}
	return themes, nil
}
func getUserFromBearerToken(token string, db *sql.DB) (*User, error) {
	query := `SELECT u.id, u.username, u.email, u.password_hash
			  FROM user u
			  JOIN bearer b ON u.id = b.user_id
			  WHERE b.token = ? AND b.expiry > DATETIME('now');`
	row := db.QueryRow(query, token)

	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
func oldBearerTokensCleanup(db *sql.DB) error {
	query := `DELETE FROM bearer WHERE expiry <= DATETIME('now');`
	_, err := db.Exec(query)
	return err
}
func makeUser(user User, db *sql.DB) error {
	query := `INSERT INTO user (username, email, password_hash) VALUES (?, ?, ?);`
	_, err := db.Exec(query, user.Username, user.Email, user.PasswordHash)
	return err
}
func getUserByEmail(email string, db *sql.DB) (*User, error) {
	query := `SELECT id, username, email, password_hash FROM user WHERE email = ?;`
	row := db.QueryRow(query, email)

	var user User
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
func updateUsername(user User, newUsername string, db *sql.DB) error {
	query := `UPDATE user SET username = ? WHERE id = ?;`
	_, err := db.Exec(query, newUsername, user.ID)
	return err
}
func GenBearerToken(user User, db *sql.DB) string {
	// first generate a random token
	token := uuid.New().String()

	// insert into bearer table with expiry a week from now (using SQLite DATETIME)
	query := `INSERT INTO bearer (token, user_id, expiry) VALUES (?, ?, DATETIME('now', '+7 days'));`
	_, err := db.Exec(query, token, user.ID)
	if err != nil {
		panic(fmt.Sprintf("error inserting bearer token into database: %v", err))
	}
	return token
}

// route handlers for theme stuff
func makeThemeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if r.FormValue("theme") == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "Missing bearer token", http.StatusUnauthorized)
			return
		}

		db := initDB()
		defer db.Close()
		theme := r.FormValue("theme")
		token := r.Header.Get("Authorization")
		tokenvalid, err := bearerTokenValid(token, db)
		if !tokenvalid || err != nil {
			http.Error(w, "Invalid or expired bearer token", http.StatusUnauthorized)
			return
		}
		user, err := getUserFromBearerToken(token, db)
		if err != nil {
			http.Error(w, "Error retrieving user from token", http.StatusInternalServerError)
			return
		}

		newTheme := Theme{
			Theme:  theme,
			UserID: sql.NullInt64{Int64: int64(user.ID), Valid: true},
		}
		err = makeTheme(newTheme, db)
		if err != nil {
			http.Error(w, "Error creating theme", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "Theme created successfully")
	case http.MethodGet:
		db := initDB()
		defer db.Close()
		limit := 10
		if r.FormValue("limit") != "" {
			fmt.Sscanf(r.FormValue("limit"), "%d", &limit)
		}
		skip := 0
		if r.FormValue("skip") != "" {
			fmt.Sscanf(r.FormValue("skip"), "%d", &skip)
		}
		themes, err := getLastfewThemes(limit, skip, db)
		if err != nil {
			http.Error(w, "Error retrieving themes", http.StatusInternalServerError)
			return
		}
		// AI code
		w.Header().Set("Content-Type", "application/json")
		type themeResp struct {
			ID     int    `json:"id"`
			Theme  string `json:"theme"`
			UserID any    `json:"user_id"`
		}
		out := make([]themeResp, 0, len(themes))
		for _, t := range themes {
			var uid any
			if t.UserID.Valid {
				uid = int(t.UserID.Int64)
			} else {
				uid = nil
			}
			out = append(out, themeResp{
				ID:     t.ID,
				Theme:  t.Theme,
				UserID: uid,
			})
		}
		if err := json.NewEncoder(w).Encode(out); err != nil {
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// route handlers for user stuff
func makeUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("username") == "" || r.FormValue("email") == "" || r.FormValue("password") == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// salt and hash password
	password := r.FormValue("password")
	passwordHash, err := hashingAndShit.HashPassword(password, 0)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// make the user struct
	newUser := User{
		Username:     r.FormValue("username"),
		Email:        r.FormValue("email"),
		PasswordHash: passwordHash,
	}
	// insert into database
	db := initDB()
	defer db.Close()
	makeUser(newUser, db)
	fmt.Fprintln(w, "User created successfully")
}
func updateUsernameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("new_username") == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	db := initDB()
	defer db.Close()
	newUsername := r.FormValue("new_username")
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Missing bearer token", http.StatusUnauthorized)
		return
	}
	tokenvalid, err := bearerTokenValid(token, db)
	if !tokenvalid || err != nil {
		http.Error(w, "Invalid or expired bearer token", http.StatusUnauthorized)
		return
	}
	jeff, err := getUserFromBearerToken(token, db)
	if err != nil {
		http.Error(w, "Error retrieving user from token", http.StatusInternalServerError)
		return
	}
	updateUsername(*jeff, newUsername, db)

}
func loginUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("email") == "" || r.FormValue("password") == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")

	db := initDB()
	defer db.Close()

	user, err := getUserByEmail(email, db)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if !hashingAndShit.CheckPasswordHash(password, user.PasswordHash) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	token := GenBearerToken(*user, db)

	fmt.Fprintf(w, "%s", token)

}

// root handler
func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome to the Study Tools API!")
}

func main() {
	fmt.Println("studytools http server!!")
	db := initDB()
	makeDBTables(db)
	oldBearerTokensCleanup(db)
	db.Close()
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/makeuser/", makeUserHandler)
	http.HandleFunc("/login/", loginUserHandler)
	http.HandleFunc("/updateusername/", updateUsernameHandler)
	http.HandleFunc("/themes/", makeThemeHandler)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("server error:", err)
	}
}
