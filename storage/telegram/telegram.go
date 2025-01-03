package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func UploadFileToTelegram(filePath string) (map[string]interface{}, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Prepare the multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add the file to the form
	part, err := writer.CreateFormFile("document", filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %v", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, fmt.Errorf("failed to write file to form: %v", err)
	}

	// Add the chat_id to the form
	writer.WriteField("chat_id", os.Getenv("TELEGRAM_CHANNEL_ID"))

	// Close the writer
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %v", err)
	}

	// Send the request to Telegram API
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", os.Getenv("TELEGRAM_BOT_TOKEN"))
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract file metadata
	result, ok := response["result"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	document, ok := result["document"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing document in response")
	}

	// Return extracted metadata
	return map[string]interface{}{
		"file_name":      document["file_name"],
		"file_id":        document["file_id"],
		"file_size":      document["file_size"],
		"file_unique_id": document["file_unique_id"],
		"mime_type":      document["mime_type"],
	}, nil
}

func RetrieveFileFromTelegram(fileID string) (string, error) {
	// Create the API URL for getting the file info
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getFile?file_id=%s", os.Getenv("TELEGRAM_BOT_TOKEN"), fileID)

	// Make the request
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve file info: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	// Check for errors in the response
	if resp.StatusCode != http.StatusOK {
		if response["description"] == "Bad Request: file is too big" {
			return "", fmt.Errorf("file size exceeds Telegram API limit of 20MB")
		}
		return "", fmt.Errorf("Telegram API error: %v", response["description"])
	}

	// Extract the file path
	result, ok := response["result"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response format")
	}

	filePath, ok := result["file_path"].(string)
	if !ok {
		return "", fmt.Errorf("file path not found in response")
	}

	// Construct the file download URL
	downloadURL := fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", os.Getenv("TELEGRAM_BOT_TOKEN"), filePath)

	// Download the file
	fileResp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download file: %v", err)
	}
	defer fileResp.Body.Close()

	// Ensure the /uploads directory exists
	uploadDir := "./uploads" // Relative path for uploads
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create upload directory: %v", err)
	}

	// Generate a unique file name
	fileName := filepath.Base(filePath) // Extract the original file name
	uniqueFilePath := filepath.Join(uploadDir, fileName)

	// Save the file locally
	file, err := os.Create(uniqueFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, fileResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to save file: %v", err)
	}

	return uniqueFilePath, nil
}
