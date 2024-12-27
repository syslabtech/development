package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	client         *mongo.Client
	userCollection *mongo.Collection
	fileCollection *mongo.Collection
	sessionData    = map[string]string{} // sessionID: userID
	mutex          = &sync.Mutex{}
	uploadDir      = "./uploads"
	secretKey      [32]byte
	// botToken       = "7407272507:" // Replace with your Telegram bot token
	// channelID      = "-"                                 // Replace with your Telegram channel ID or username
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Password string             `bson:"password"`
	Salt     string             `bson:"salt"`
}

type File struct {
	UserID     primitive.ObjectID `bson:"user_id"`
	Filename   string             `bson:"filename"`
	UploadDate time.Time          `bson:"uploadDate"`
}

type EncryptionKey struct {
	ID  primitive.ObjectID `bson:"_id,omitempty"`
	Key []byte             `bson:"key"`
}

func generateSalt() (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func hashPassword(password, salt string) string {
	saltBytes := []byte(salt)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash)
}

func verifyPassword(hash, password, salt string) bool {
	expectedHash := hashPassword(password, salt)
	return hash == expectedHash
}

func init() {
	// Connect to MongoDB
	uri := "mongodb+srv://filemanager:lQs8uz3A4WI4AtjL@choreo.06gdy.mongodb.net/?retryWrites=true&w=majority&appName=choreo&tls=true"

	clientOptions := options.Client().ApplyURI(uri)

	// Add a monitor for command events
	clientOptions.SetMonitor(&event.CommandMonitor{
		Started: func(ctx context.Context, evt *event.CommandStartedEvent) {
			log.Printf("MongoDB Command Started: %s\n", evt.Command)
		},
		Succeeded: func(ctx context.Context, evt *event.CommandSucceededEvent) {
			log.Printf("MongoDB Command Succeeded: %s\n", evt.CommandName)
		},
		Failed: func(ctx context.Context, evt *event.CommandFailedEvent) {
			log.Printf("MongoDB Command Failed: %s\n", evt.CommandName)
		},
	})

	// Optional: Configure TLS if needed
	// tlsConfig := &tls.Config{InsecureSkipVerify: true} // Use with caution
	// clientOptions.SetTLSConfig(tlsConfig)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Ping MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("MongoDB Ping Error: %v", err)
	}

	// Collections
	keyCollection := client.Database("filemanager").Collection("keys")
	userCollection = client.Database("filemanager").Collection("users")
	fileCollection = client.Database("filemanager").Collection("files")

	// Ensure the upload directory exists
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		err := os.Mkdir(uploadDir, 0755)
		if err != nil {
			log.Fatalf("Failed to create upload directory: %v", err)
		}
	}

	// Retrieve the encryption key from MongoDB
	var encryptionKey EncryptionKey
	err = keyCollection.FindOne(context.Background(), bson.M{}).Decode(&encryptionKey)
	if err == mongo.ErrNoDocuments {
		// Generate a new key if none exists
		if _, err := io.ReadFull(rand.Reader, secretKey[:]); err != nil {
			log.Fatalf("Failed to generate encryption key: %v", err)
		}

		// Store the new key in MongoDB
		_, err = keyCollection.InsertOne(context.Background(), EncryptionKey{Key: secretKey[:]})
		if err != nil {
			log.Fatalf("Failed to store encryption key: %v", err)
		}
	} else if err != nil {
		log.Fatalf("Error retrieving encryption key: %v", err)
	} else {
		// Use the retrieved key
		copy(secretKey[:], encryptionKey.Key)
	}
	log.Println("Connected DB")
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
	// var err error
	// clientOptions := options.Client().ApplyURI("mongodb+srv://filemanager:G30752G5JQc8tIa2yzi0UN4fV@choreo.06gdy.mongodb.net/?retryWrites=true&w=majority&appName=choreo")
	// client, err = mongo.Connect(context.Background(), clientOptions)
	// if err != nil {
	// 	panic(err)
	// }

	// Ensure MongoDB client is connected
	// err = client.Ping(context.Background(), nil)
	// if err != nil {
	// 	panic(err)
	// }

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

func encryptFile(inputFile, outputFile string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	data, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, &secretKey)

	return os.WriteFile(outputFile, encrypted, 0644)
}

func decryptFile(inputFile, outputFile string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	encrypted, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, &secretKey)
	if !ok {
		return errors.New("decryption error")
	}

	return os.WriteFile(outputFile, decrypted, 0644)
}

// Home Handler
func homeHandler(w http.ResponseWriter, r *http.Request) {

	target := "http://localhost:8080" // Backend server
	proxyURL, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(proxyURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Modify response headers if needed
		resp.Header.Set("Content-Length", "100000000")
		return nil
	}

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
	// fmt.Println("Files found:", files)

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

		// Find the user in MongoDB
		var user User
		err := userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Verify the password
		if !verifyPassword(user.Password, password, user.Salt) {
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

		// Check if the user already exists
		var user User
		err := userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
		if err == nil {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		// Generate a unique salt
		salt, err := generateSalt()
		if err != nil {
			http.Error(w, "Unable to generate salt", http.StatusInternalServerError)
			return
		}

		// Hash the password using Argon2
		hashedPassword := hashPassword(password, salt)

		// Save the user to MongoDB
		userID := primitive.NewObjectID()
		_, err = userCollection.InsertOne(context.Background(), User{
			ID:       userID,
			Username: username,
			Password: hashedPassword,
			Salt:     salt, // Store the salt
		})
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
	tempFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.tmp", userIDHex, handler.Filename))
	dst, err := os.Create(tempFilePath)
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

	// Encrypt the file
	encryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.enc", userIDHex, handler.Filename))
	err = encryptFile(tempFilePath, encryptedFilePath)
	if err != nil {
		http.Error(w, "Unable to encrypt file", http.StatusInternalServerError)
		return
	}

	// Upload the file to Telegram
	// err = uploadFileToTelegram(encryptedFilePath)
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("Failed to upload file to Telegram: %v", err), http.StatusInternalServerError)
	// 	return
	// }

	// Remove the temporary file
	os.Remove(tempFilePath)

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
	encryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.enc", userIDHex, fileName))
	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Decrypt the file
	decryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", userIDHex, fileName))
	err = decryptFile(encryptedFilePath, decryptedFilePath)
	if err != nil {
		http.Error(w, "Unable to decrypt file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(decryptedFilePath)

	// Set the headers for file download
	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	http.ServeFile(w, r, decryptedFilePath)

}

// func uploadFileToTelegram(filePath string) error {
// 	// Open the file
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		return fmt.Errorf("failed to open file: %v", err)
// 	}
// 	defer file.Close()

// 	// Get file info for the name
// 	fileInfo, err := file.Stat()
// 	if err != nil {
// 		return fmt.Errorf("failed to stat file: %v", err)
// 	}

// 	// Create a multipart form
// 	body := &bytes.Buffer{}
// 	writer := multipart.NewWriter(body)

// 	// Add the file to the form
// 	part, err := writer.CreateFormFile("document", fileInfo.Name())
// 	if err != nil {
// 		return fmt.Errorf("failed to create form file: %v", err)
// 	}
// 	if _, err = io.Copy(part, file); err != nil {
// 		return fmt.Errorf("failed to write file to form: %v", err)
// 	}

// 	// Add the channel ID to the form
// 	if err = writer.WriteField("chat_id", channelID); err != nil {
// 		return fmt.Errorf("failed to write chat_id: %v", err)
// 	}

// 	// Close the writer
// 	if err = writer.Close(); err != nil {
// 		return fmt.Errorf("failed to close writer: %v", err)
// 	}

// 	// Create and send the request
// 	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", botToken)
// 	req, err := http.NewRequest("POST", url, body)
// 	if err != nil {
// 		return fmt.Errorf("failed to create request: %v", err)
// 	}
// 	req.Header.Set("Content-Type", writer.FormDataContentType())

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return fmt.Errorf("failed to send request: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	// Check the response status
// 	if resp.StatusCode != http.StatusOK {
// 		return fmt.Errorf("unexpected response status: %v", resp.Status)
// 	}

// 	fmt.Println("File uploaded successfully!")
// 	return nil
// }

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
	// Generate the file path based on the user ID and file name
	encryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.enc", userIDHex, fileName))
	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	err = os.Remove(encryptedFilePath)
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
// func previewHandler(w http.ResponseWriter, r *http.Request) {
// 	// Get the session cookie
// 	cookie, err := r.Cookie("session")
// 	if err != nil {
// 		log.Printf("Error retrieving session cookie: %v\n", err)
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return
// 	}

// 	// Retrieve the user ID from the session
// 	userIDHex, ok := sessionData[cookie.Value]
// 	if !ok {
// 		log.Printf("Invalid session ID: %v\n", cookie.Value)
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return
// 	}

// 	userID, err := primitive.ObjectIDFromHex(userIDHex)
// 	if err != nil {
// 		log.Printf("Error decoding user ID: %v\n", err)
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return
// 	}

// 	// Extract the file name from the URL path
// 	fileName := filepath.Clean(filepath.Base(r.URL.Path))

// 	// Check if the file belongs to the user in MongoDB
// 	var file File
// 	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "filename": fileName}).Decode(&file)
// 	if err != nil {
// 		log.Printf("Unauthorized access to file: %v\n", fileName)
// 		http.Error(w, "Unauthorized to preview this file", http.StatusUnauthorized)
// 		return
// 	}

// 	// Generate the file path based on the user ID and file name
// 	encryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.enc", userIDHex, fileName))
// 	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
// 		log.Printf("File not found: %v\n", encryptedFilePath)
// 		http.Error(w, "File not found", http.StatusNotFound)
// 		return
// 	}

// 	// Decrypt the file into a temporary location
// 	tempFile, err := os.CreateTemp("", fmt.Sprintf("%s_*_%s", userIDHex, fileName))
// 	if err != nil {
// 		log.Printf("Error creating temporary file: %v\n", err)
// 		http.Error(w, "Unable to decrypt file", http.StatusInternalServerError)
// 		return
// 	}
// 	defer os.Remove(tempFile.Name())

// 	err = decryptFile(encryptedFilePath, tempFile.Name())
// 	if err != nil {
// 		log.Printf("Error decrypting file: %v\n", err)
// 		http.Error(w, "Unable to decrypt file", http.StatusInternalServerError)
// 		return
// 	}

// 	// Determine the content type from the file content
// 	buffer := make([]byte, 512)
// 	tempFile.Seek(0, 0)
// 	tempFile.Read(buffer)
// 	contentType := http.DetectContentType(buffer)
// 	tempFile.Seek(0, 0)

// 	// Restrict supported file types
// 	if !strings.HasPrefix(contentType, "image/") && contentType != "application/pdf" {
// 		log.Printf("Unsupported file type: %v\n", contentType)
// 		http.Error(w, "Unsupported file type for preview", http.StatusUnsupportedMediaType)
// 		return
// 	}

//		// Serve the decrypted file for preview
//		w.Header().Set("Content-Type", contentType)
//		http.ServeFile(w, r, tempFile.Name())
//	}
func previewHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		logAndRedirect(w, r, "Error retrieving session cookie", "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the user ID from the session
	userIDHex, ok := sessionData[cookie.Value]
	if !ok {
		logAndRedirect(w, r, "Invalid session ID", "/login", http.StatusSeeOther)
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		logAndRedirect(w, r, "Error decoding user ID", "/login", http.StatusSeeOther)
		return
	}

	// Extract and sanitize the file name from the URL path
	fileName := filepath.Clean(filepath.Base(r.URL.Path))
	if fileName == "." || fileName == "/" {
		logAndRespond(w, "Invalid file name", http.StatusBadRequest)
		return
	}

	// Check if the file belongs to the user in MongoDB
	var file File
	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "filename": fileName}).Decode(&file)
	if err != nil {
		logAndRespond(w, fmt.Sprintf("Unauthorized access to file: %v", fileName), http.StatusUnauthorized)
		return
	}

	// Locate the encrypted file
	encryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.enc", userIDHex, fileName))
	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
		logAndRespond(w, fmt.Sprintf("File not found: %v", encryptedFilePath), http.StatusNotFound)
		return
	}

	// Decrypt the file into a temporary location
	tempFile, err := os.CreateTemp("", fmt.Sprintf("%s_*_%s", userIDHex, fileName))
	if err != nil {
		logAndRespond(w, "Error creating temporary file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())

	err = decryptFile(encryptedFilePath, tempFile.Name())
	if err != nil {
		logAndRespond(w, "Error decrypting file", http.StatusInternalServerError)
		return
	}

	// Detect file type and validate it
	buffer := make([]byte, 512)
	tempFile.Seek(0, 0)
	tempFile.Read(buffer)
	contentType := http.DetectContentType(buffer)
	tempFile.Seek(0, 0)

	// Supported content types for preview
	supportedTypes := map[string]bool{
		"image/":           true,
		"application/pdf":  true,
		"text/plain":       true,
		"application/json": true,
		"video/":           true, // Video support
	}

	if !isSupportedContent(contentType, supportedTypes) {
		logAndRespond(w, fmt.Sprintf("Unsupported file type: %v", contentType), http.StatusUnsupportedMediaType)
		return
	}

	// Serve the file content for preview
	w.Header().Set("Content-Type", contentType)
	http.ServeFile(w, r, tempFile.Name())
}

// Helper to log an error and redirect
func logAndRedirect(w http.ResponseWriter, r *http.Request, logMessage, redirectURL string, statusCode int) {
	log.Printf("%s\n", logMessage)
	http.Redirect(w, r, redirectURL, statusCode)
}

// Helper to log an error and respond with an HTTP status
func logAndRespond(w http.ResponseWriter, logMessage string, statusCode int) {
	log.Printf("%s\n", logMessage)
	http.Error(w, logMessage, statusCode)
}

// Helper to check if the content type is supported
func isSupportedContent(contentType string, supportedTypes map[string]bool) bool {
	for prefix := range supportedTypes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

// ...existing code...

func shareHandler(w http.ResponseWriter, r *http.Request) {
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

	// Generate the shareable link
	shareableLink := fmt.Sprintf("%s/download/%s", r.Host, fileName)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"shareable_link": "%s"}`, shareableLink)))
}
