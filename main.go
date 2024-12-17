package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// In-code user database
var (
	users       = map[string]string{"admin": "password"} // username: password
	userFiles   = map[string][]string{}                 // username: [files]
	sessionData = map[string]string{}                   // sessionID: username
	mutex       = &sync.Mutex{}
)

const (
	uploadDir = "./uploads"
)

// Middleware to check authentication
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || sessionData[cookie.Value] == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func main() {
	// Ensure the upload directory exists
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		err := os.Mkdir(uploadDir, 0755)
		if err != nil {
			panic(err)
		}
	}

	// Set up routes
	http.HandleFunc("/", authMiddleware(homeHandler))
	http.HandleFunc("/upload", authMiddleware(uploadHandler))
	http.HandleFunc("/download/", authMiddleware(downloadHandler))
	http.HandleFunc("/delete/", authMiddleware(deleteHandler))
	http.HandleFunc("/preview/", authMiddleware(previewHandler))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/register", registerHandler)

	fmt.Println("Server started at http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

// Home Handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the username from the session data
	username := sessionData[cookie.Value]
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get the user's files
	files := userFiles[username]

	// Render the template
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	err = tmpl.Execute(w, files)
	if err != nil {
		http.Error(w, "Unable to render template", http.StatusInternalServerError)
	}
}

// Login Handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		mutex.Lock()
		defer mutex.Unlock()

		if pass, exists := users[username]; exists && pass == password {
			sessionID := fmt.Sprintf("%d", len(sessionData)+1)
			sessionData[sessionID] = username
			http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionID, Path: "/"})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

// Logout Handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		mutex.Lock()
		delete(sessionData, cookie.Value)
		mutex.Unlock()
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Register Handler
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		mutex.Lock()
		defer mutex.Unlock()

		if _, exists := users[username]; exists {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		users[username] = password
		userFiles[username] = []string{}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/register.html"))
	tmpl.Execute(w, nil)
}

// Upload Handler
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the username from the session
	username := sessionData[cookie.Value]
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the uploaded file
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save the file with a unique name for the user
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", username, handler.Filename))
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Unable to save file", http.StatusInternalServerError)
		return
	}

	// Add the file to the user's list
	mutex.Lock()
	userFiles[username] = append(userFiles[username], handler.Filename)
	mutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Download Handler
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the username from the session
	username := sessionData[cookie.Value]
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the file name from the URL path
	fileName := filepath.Base(r.URL.Path)

	// Check if the file belongs to the user
	mutex.Lock()
	userFilesList, exists := userFiles[username]
	mutex.Unlock()

	if !exists || !contains(userFilesList, fileName) {
		http.Error(w, "Unauthorized to access this file", http.StatusUnauthorized)
		return
	}

	// Generate the file path based on the username and file name
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", username, fileName))
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Set the headers for file download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	http.ServeFile(w, r, filePath)
}

// Delete Handler
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the username from the session
	username := sessionData[cookie.Value]
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the file name from the URL path
	fileName := filepath.Base(r.URL.Path)

	// Check if the file belongs to the user
	mutex.Lock()
	userFilesList, exists := userFiles[username]
	if !exists || !contains(userFilesList, fileName) {
		mutex.Unlock()
		http.Error(w, "Unauthorized to delete this file", http.StatusUnauthorized)
		return
	}

	// Remove the file from the file system
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", username, fileName))
	err = os.Remove(filePath)
	if err != nil {
		mutex.Unlock()
		http.Error(w, "Unable to delete file", http.StatusInternalServerError)
		return
	}

	// Update the user's file list
	userFiles[username] = removeFileFromList(userFilesList, fileName)
	mutex.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Preview Handler
func previewHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the username from the session
	username := sessionData[cookie.Value]
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the file name from the URL path
	fileName := filepath.Base(r.URL.Path)

	// Check if the file belongs to the user
	mutex.Lock()
	userFilesList, exists := userFiles[username]
	if !exists || !contains(userFilesList, fileName) {
		mutex.Unlock()
		http.Error(w, "Unauthorized to preview this file", http.StatusUnauthorized)
		return
	}

	// Check if the file exists
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", username, fileName))
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		mutex.Unlock()
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Serve the file for preview
	http.ServeFile(w, r, filePath)
	mutex.Unlock()
}

// Helper functions

func contains(files []string, fileName string) bool {
	for _, f := range files {
		if f == fileName {
			return true
		}
	}
	return false
}

func removeFileFromList(files []string, fileName string) []string {
	var updatedFiles []string
	for _, f := range files {
		if f != fileName {
			updatedFiles = append(updatedFiles, f)
		}
	}
	return updatedFiles
}
