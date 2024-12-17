package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	client         *mongo.Client
	userCollection *mongo.Collection
	fileCollection *mongo.Collection
	sessionData    = map[string]string{} // sessionID: userID
	mutex          = &sync.Mutex{}
	uploadDir      = "./uploads"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Password string             `bson:"password"`
}

type File struct {
	UserID     primitive.ObjectID `bson:"user_id"`
	Filename   string             `bson:"filename"`
	UploadDate time.Time          `bson:"uploadDate"`
}

// func init() {
// 	// Load environment variables from the .env file
// 	err := godotenv.Load()
// 	if err != nil {
// 		log.Fatalf("Error loading .env file: %v", err)
// 	}

// 	// Get the Vault address, HCP Client ID, and HCP Client Secret from environment variables
// 	vaultAddr := os.Getenv("VAULT_ADDR")
// 	hcpClientID := os.Getenv("HCP_CLIENT_ID")
// 	hcpClientSecret := os.Getenv("HCP_CLIENT_SECRET")

// 	// Initialize the Vault client
// 	client, err := api.NewClient(&api.Config{
// 		Address: vaultAddr, // Use the Vault address from environment variable
// 	})
// 	if err != nil {
// 		log.Fatalf("Error creating Vault client: %v", err)
// 	}

// 	// Set up authentication data for HCP Vault
// 	authData := map[string]interface{}{
// 		"client_id":     hcpClientID,
// 		"client_secret": hcpClientSecret,
// 	}

// 	// Authenticate with HCP Vault and retrieve a Vault token
// 	// Making a direct API request for authentication
// 	authResponse, err := client.Logical().Write("auth/hcp/login", authData)
// 	if err != nil {
// 		log.Fatalf("Error authenticating with HCP credentials: %v", err)
// 	}

// 	// Check if we received the client token from the authentication response
// 	if authResponse == nil || authResponse.Auth == nil {
// 		log.Fatalf("Authentication failed, no token returned")
// 	}

// 	// Set the Vault token for subsequent requests
// 	client.SetToken(authResponse.Auth.ClientToken)

// 	// Specify the path to the secret (for example, "secret/data/my-secret")
// 	secretPath := "secret/data/my-secret" // Adjust the path to your secret

// 	// Retrieve the secret from Vault
// 	secret, err := client.Logical().Read(secretPath)
// 	if err != nil {
// 		log.Fatalf("Error reading secret from Vault: %v", err)
// 	}

// 	// Check if the secret was found
// 	if secret == nil {
// 		log.Fatalf("Secret not found at path %s", secretPath)
// 	}

// 	// Extract the value from the secret
// 	// Assuming the secret is stored as a key-value pair, e.g., {"data": {"my-key": "my-value"}}
// 	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
// 		if myValue, ok := data["my-key"].(string); ok {
// 			fmt.Printf("Retrieved secret value: %s\n", myValue)
// 		} else {
// 			log.Fatalf("Key 'my-key' not found in the secret data")
// 		}
// 	} else {
// 		log.Fatalf("Invalid secret structure")
// 	}

// }

func main() {
	// Connect to MongoDB
	var err error
	clientOptions := options.Client().ApplyURI("mongodb+srv://filemanager:G30752G5JQc8tIa2yzi0UN4fV@choreo.06gdy.mongodb.net/?retryWrites=true&w=majority&appName=choreo")
	client, err = mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		panic(err)
	}

	// Ensure MongoDB client is connected
	err = client.Ping(context.Background(), nil)
	if err != nil {
		panic(err)
	}

	// Initialize collections
	userCollection = client.Database("filemanager").Collection("users")
	fileCollection = client.Database("filemanager").Collection("files")

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
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

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

// Home Handler
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the user ID from the session data
	userIDHex := sessionData[cookie.Value]
	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	// Retrieve the user's files from MongoDB
	var files []File
	cursor, err := fileCollection.Find(context.Background(), bson.M{"user_id": userID, "deleted": bson.M{"$ne": true}})
	if err != nil {
		http.Error(w, "Unable to retrieve files", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var file File
		err := cursor.Decode(&file)
		if err != nil {
			http.Error(w, "Unable to decode file", http.StatusInternalServerError)
			return
		}
		files = append(files, file)
	}

	// Debugging line to print files
	fmt.Println("Files found:", files)

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

		// Find user in MongoDB
		var user User
		err := userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
		if err != nil || user.Password != password {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Set session
		sessionID := fmt.Sprintf("%d", len(sessionData)+1)
		sessionData[sessionID] = user.ID.Hex()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: sessionID, Path: "/"})
		http.Redirect(w, r, "/", http.StatusSeeOther)
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

		// Check if user already exists
		var user User
		err := userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
		if err == nil {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		// Insert new user into MongoDB
		userID := primitive.NewObjectID()
		_, err = userCollection.InsertOne(context.Background(), User{ID: userID, Username: username, Password: password})
		if err != nil {
			http.Error(w, "Unable to register user", http.StatusInternalServerError)
			return
		}

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

	// Retrieve the user ID from the session
	userIDHex := sessionData[cookie.Value]
	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
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
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", userIDHex, handler.Filename))
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

	// Add file metadata to MongoDB
	_, err = fileCollection.InsertOne(context.Background(), File{UserID: userID, Filename: handler.Filename, UploadDate: time.Now()})
	if err != nil {
		http.Error(w, "Unable to save file metadata", http.StatusInternalServerError)
		return
	}

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

	// Retrieve the user ID from the session
	userIDHex := sessionData[cookie.Value]
	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the file name from the URL path
	fileName := filepath.Base(r.URL.Path)

	// Check if the file belongs to the user in MongoDB
	var file File
	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "filename": fileName}).Decode(&file)
	if err != nil {
		http.Error(w, "Unauthorized to access this file", http.StatusUnauthorized)
		return
	}

	// Generate the file path based on the user ID and file name
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", userIDHex, fileName))
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Set the headers for file download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	http.ServeFile(w, r, filePath)
}

// Delete Handler  Soft Delete
// func deleteHandler(w http.ResponseWriter, r *http.Request) {
//     // Get the session cookie
//     cookie, err := r.Cookie("session")
//     if err != nil {
//         http.Redirect(w, r, "/login", http.StatusSeeOther)
//         return
//     }

//     // Retrieve the user ID from the session
//     userIDHex := sessionData[cookie.Value]
//     userID, err := primitive.ObjectIDFromHex(userIDHex)
//     if err != nil {
//         http.Redirect(w, r, "/login", http.StatusSeeOther)
//         return
//     }

//     // Extract the file name from the URL path
//     fileName := filepath.Base(r.URL.Path)

//     // Check if the file belongs to the user in MongoDB
//     var file File
//     err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "filename": fileName, "deleted": bson.M{"$ne": true}}).Decode(&file)
//     if err != nil {
//         http.Error(w, "Unauthorized to delete this file", http.StatusUnauthorized)
//         return
//     }

//     // Flag the file as deleted in MongoDB
//     update := bson.M{"$set": bson.M{"deleted": true}}
//     _, err = fileCollection.UpdateOne(context.Background(), bson.M{"user_id": userID, "filename": fileName}, update)
//     if err != nil {
//         http.Error(w, "Unable to update file metadata", http.StatusInternalServerError)
//         return
//     }

//     // Optional: Log or perform other operations (e.g., send a notification, etc.)

//     // Redirect back to the home page (or wherever you want)
//     http.Redirect(w, r, "/", http.StatusSeeOther)
// }

// Soft Delete
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the user ID from the session
	userIDHex := sessionData[cookie.Value]
	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the file name from the URL path
	fileName := filepath.Base(r.URL.Path)

	// Check if the file belongs to the user in MongoDB
	var file File
	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "filename": fileName}).Decode(&file)
	if err != nil {
		http.Error(w, "Unauthorized to delete this file", http.StatusUnauthorized)
		return
	}

	// Remove the file from the file system
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", userIDHex, fileName))
	err = os.Remove(filePath)
	if err != nil {
		http.Error(w, "Unable to delete file", http.StatusInternalServerError)
		return
	}

	// Update file metadata to mark it as deleted in MongoDB
	_, err = fileCollection.UpdateOne(
		context.Background(),
		bson.M{"user_id": userID, "filename": fileName},
		bson.M{"$set": bson.M{"deleted": true}},
	)
	if err != nil {
		http.Error(w, "Unable to update file metadata", http.StatusInternalServerError)
		return
	}

	// Redirect back to the home page
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

	// Retrieve the user ID from the session
	userIDHex := sessionData[cookie.Value]
	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Extract the file name from the URL path
	fileName := filepath.Base(r.URL.Path)

	// Check if the file belongs to the user in MongoDB
	var file File
	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "filename": fileName}).Decode(&file)
	if err != nil {
		http.Error(w, "Unauthorized to preview this file", http.StatusUnauthorized)
		return
	}

	// Serve the file for preview
	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", userIDHex, fileName))
	http.ServeFile(w, r, filePath)
}
