package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"filemanager/storage/doppler"
	"filemanager/storage/telegram"
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

	"github.com/joho/godotenv"
	"github.com/newrelic/go-agent/v3/newrelic"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	// Replace with your Telegram channel ID or username
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username"`
	Password string             `bson:"password"`
	Salt     string             `bson:"salt"`
}

type FileMetadata struct {
	ID           primitive.ObjectID `bson:"_id"`
	MimeType     string             `bson:"mime_type"`
	UploadDate   time.Time          `bson:"upload_date"`
	UserID       primitive.ObjectID `bson:"user_id"`
	File         string             `bson:"file"`
	FileName     string             `bson:"file_name"`
	FileID       string             `bson:"file_id"`
	FileSize     int64              `bson:"file_size"`
	FileUniqueID string             `bson:"file_unique_id"`
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

	// Get the current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print the current working directory
	fmt.Println("Current Directory:", currentDir)

	// Read the entire file content
	// content, err := ioutil.ReadFile("/workspace/.env")
	// if err != nil {
	// 	log.Fatalf("Error reading file: %v", err)
	// }

	// Print the file content as a string
	// fmt.Println("File Content:")
	// fmt.Println(string(content))

	_ = godotenv.Load()

	// Retrive critical information
	doppler.FetchDopplerData()

}

func initEncryptionKey(keyCollection *mongo.Collection) {
	mutex.Lock() // Ensure only one instance can initialize the key at a time
	defer mutex.Unlock()

	// Attempt to retrieve the key
	var encryptionKey EncryptionKey
	err := keyCollection.FindOne(context.Background(), bson.M{}).Decode(&encryptionKey)
	if err == mongo.ErrNoDocuments {
		fmt.Println("No encryption key found; generating a new key...")

		// Generate a new key
		if _, err := io.ReadFull(rand.Reader, secretKey[:]); err != nil {
			log.Fatalf("Failed to generate encryption key: %v", err)
		}

		// Store the new key in MongoDB
		_, err = keyCollection.InsertOne(context.Background(), EncryptionKey{Key: secretKey[:]})
		if err != nil {
			log.Fatalf("Failed to store encryption key: %v", err)
		}

		fmt.Println("New encryption key successfully generated and stored.")
	} else if err != nil {
		log.Fatalf("Error retrieving encryption key: %v", err)
	} else {
		// Use the retrieved key
		copy(secretKey[:], encryptionKey.Key)
		fmt.Println("Encryption key successfully retrieved.")
	}
}

func main() {

	// Connect to MongoDB
	uri := os.Getenv("MONGODB_CONNECTION")
	clientOptions := options.Client().ApplyURI(uri)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
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

	// Initialize the encryption key
	initEncryptionKey(keyCollection)

	log.Println("Connected DB")

	// Set up routes
	http.HandleFunc("/", authMiddleware(homeHandler))
	http.HandleFunc("/upload", authMiddleware(uploadHandler))
	http.HandleFunc("/download/", authMiddleware(downloadHandler))
	http.HandleFunc("/delete/", authMiddleware(deleteHandler))
	http.HandleFunc("/preview/", authMiddleware(previewHandler))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc(newrelic.WrapHandleFunc(newrelicApp(), "/home", homeHandler))

	fmt.Println("Server started at http://localhost:8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

func newrelicApp() (app *newrelic.Application) {
	app, _ = newrelic.NewApplication(
		newrelic.ConfigAppName("File Manager"),
		newrelic.ConfigLicense("511c42284fa5dec03f4c6393957e84c7FFFFNRAL"),
		newrelic.ConfigAppLogForwardingEnabled(true),
	)
	txn := app.StartTransaction("transaction_name")
	defer txn.End()
	return
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
	var files []FileMetadata
	cursor, err := fileCollection.Find(context.Background(), bson.M{"user_id": userID, "deleted": bson.M{"$ne": true}})
	if err != nil {
		http.Error(w, "Unable to retrieve files", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var file FileMetadata
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
		log.Fatalf("Error parsing template: %v", err)

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

	// Example: Validate file size
	fileSize := r.ContentLength
	if err := validateFileSize(fileSize); err != nil {
		logAndRespond(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Retrieve the uploaded file
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Generate the file names (without directory)
	baseFileName := fmt.Sprintf("%s_%s", userIDHex, handler.Filename)
	originalFilePath := filepath.Join(uploadDir, baseFileName)
	// encryptedFileName := fmt.Sprintf("%s.enc", baseFileName)
	// encryptedFilePath := filepath.Join(uploadDir, encryptedFileName)

	// Save the original file
	dst, err := os.Create(originalFilePath)
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
	// err = encryptFile(originalFilePath, encryptedFilePath)
	// if err != nil {
	// 	http.Error(w, "Unable to encrypt file", http.StatusInternalServerError)
	// 	return
	// }

	// Upload the original file to Telegram
	telegramMetadata, err := telegram.UploadFileToTelegram(originalFilePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to upload normal file to Telegram: %v", err), http.StatusInternalServerError)
		return
	}

	// // Upload the encrypted file to Telegram
	// err = uploadFileToTelegram(encryptedFilePath)
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("Failed to upload encrypted file to Telegram: %v", err), http.StatusInternalServerError)
	// 	return
	// }

	// Add file metadata with sanitized paths to MongoDB
	// _, err = fileCollection.InsertOne(context.Background(), bson.M{
	// 	"user_id":             userID,
	// 	"filename":            handler.Filename,
	// 	"original_file_path":  baseFileName,      // Only filename
	// 	"encrypted_file_path": encryptedFileName, // Only filename
	// 	"upload_date":         time.Now(),
	// })

	// Add file metadata with Telegram details to MongoDB
	_, err = fileCollection.InsertOne(context.Background(), bson.M{
		"user_id":        userID,
		"file":           handler.Filename,
		"file_name":      telegramMetadata["file_name"],
		"file_id":        telegramMetadata["file_id"],
		"file_size":      telegramMetadata["file_size"],
		"file_unique_id": telegramMetadata["file_unique_id"],
		"mime_type":      telegramMetadata["mime_type"],
		"upload_date":    time.Now(),
	})

	if err != nil {
		http.Error(w, "Unable to save file metadata", http.StatusInternalServerError)
		return
	}

	// Remove the temporary files
	os.Remove(originalFilePath)
	// os.Remove(encryptedFilePath)

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

	// Extract the file ID from the URL query parameter
	fileID := r.URL.Query().Get("id")
	if fileID == "" {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	fileObjID, err := primitive.ObjectIDFromHex(fileID)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Check if the file belongs to the user in MongoDB
	var file FileMetadata
	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "_id": fileObjID}).Decode(&file)
	if err != nil {
		log.Printf("MongoDB query error: %v", err)
		http.Error(w, "Unauthorized to access this file", http.StatusUnauthorized)
		return
	}

	// Retrieve the file from Telegram API
	filePath, err := telegram.RetrieveFileFromTelegram(file.FileID)
	if err != nil {
		http.Error(w, "Unable to retrieve file from Telegram: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(filePath) // Clean up temporary file after serving

	// Set the headers for file download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.File))
	http.ServeFile(w, r, filePath)
}

// Delete Handler  Soft Delete
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

	// Extract the file ID (ObjectID) from the URL path
	fileIDHex := filepath.Base(r.URL.Path)
	fileID, err := primitive.ObjectIDFromHex(fileIDHex)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Check if the file belongs to the user in MongoDB
	var file FileMetadata
	err = fileCollection.FindOne(context.Background(), bson.M{
		"_id":     fileID,
		"user_id": userID,
		"deleted": bson.M{"$ne": true},
	}).Decode(&file)
	if err != nil {
		http.Error(w, "Unauthorized to delete this file", http.StatusUnauthorized)
		return
	}

	// Flag the file as deleted in MongoDB
	update := bson.M{"$set": bson.M{"deleted": true}}
	_, err = fileCollection.UpdateOne(context.Background(), bson.M{"_id": fileID, "user_id": userID}, update)
	if err != nil {
		http.Error(w, "Unable to update file metadata", http.StatusInternalServerError)
		return
	}

	// Optional: Additional cleanup, logging, or notification logic

	// Redirect back to the home page (or wherever you want)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Hard Delete
// func deleteHandler(w http.ResponseWriter, r *http.Request) {
// 	// Get the session cookie
// 	cookie, err := r.Cookie("session")
// 	if err != nil {
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return
// 	}

// 	// Retrieve the user ID from the session
// 	userIDHex := sessionData[cookie.Value]
// 	userID, err := primitive.ObjectIDFromHex(userIDHex)
// 	if err != nil {
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		return
// 	}

// 	// Extract the file ID from the URL path
// 	fileIDHex := filepath.Base(r.URL.Path)
// 	fileID, err := primitive.ObjectIDFromHex(fileIDHex)
// 	if err != nil {
// 		http.Error(w, "Invalid file ID", http.StatusBadRequest)
// 		return
// 	}

// 	// Check if the file belongs to the user in MongoDB
// 	var file FileMetadata
// 	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "_id": fileID}).Decode(&file)
// 	if err != nil {
// 		http.Error(w, "Unauthorized to delete this file", http.StatusUnauthorized)
// 		return
// 	}

// 	// Remove the file from the file system
// 	encryptedFilePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s.enc", userID.Hex(), file.File))
// 	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
// 		http.Error(w, "File not found", http.StatusNotFound)
// 		return
// 	}

// 	err = os.Remove(encryptedFilePath)
// 	if err != nil {
// 		http.Error(w, "Unable to delete file", http.StatusInternalServerError)
// 		return
// 	}

// 	// Mark the file as deleted in MongoDB
// 	_, err = fileCollection.UpdateOne(
// 		context.Background(),
// 		bson.M{"_id": fileID, "user_id": userID},
// 		bson.M{"$set": bson.M{"deleted": true}},
// 	)
// 	if err != nil {
// 		http.Error(w, "Unable to update file metadata", http.StatusInternalServerError)
// 		return
// 	}

// 	// Redirect back to the home page
// 	http.Redirect(w, r, "/", http.StatusSeeOther)
// }

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

	// Extract and sanitize the ObjectID from the URL query parameters
	objectIDHex := r.URL.Query().Get("id") // Use the `id` from the URL query parameters
	fmt.Println("objectIDHex: ", objectIDHex)
	if objectIDHex == "" {
		logAndRespond(w, "Invalid ObjectID", http.StatusBadRequest)
		return
	}

	// Convert the ObjectIDHex (string) to a primitive.ObjectID
	objectID, err := primitive.ObjectIDFromHex(objectIDHex)
	if err != nil {
		logAndRespond(w, "Invalid ObjectID format", http.StatusBadRequest)
		return
	}

	// Check if the file belongs to the user in MongoDB
	var file FileMetadata
	err = fileCollection.FindOne(context.Background(), bson.M{"user_id": userID, "_id": objectID}).Decode(&file)
	if err != nil {
		logAndRespond(w, fmt.Sprintf("Unauthorized access to file: %v", objectIDHex), http.StatusUnauthorized)
		return
	}

	filePath, err := telegram.RetrieveFileFromTelegram(file.FileID) // Use file_id from Telegram metadata
	if err != nil {
		log.Printf("Failed to retrieve file from Telegram: %v", err)
		logAndRespond(w, "Error retrieving file from Telegram", http.StatusInternalServerError)
		return
	}

	// Detect file type and validate it
	tempFile, err := os.Open(filePath)
	if err != nil {
		logAndRespond(w, "Error opening file for preview", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()

	buffer := make([]byte, 512)
	tempFile.Read(buffer)
	contentType := http.DetectContentType(buffer)

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
	http.ServeFile(w, r, filePath)
}

// retrieveFileFromTelegram fetches a file from Telegram using its file ID.

func validateFileSize(fileSize int64) error {
	if fileSize > 20*1024*1024 { // 20MB limit
		return fmt.Errorf("file size exceeds Telegram API limit of 20MB")
	}
	return nil
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
