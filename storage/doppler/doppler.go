package doppler

import (
	"encoding/json"
	"filemanager/core"
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	projectName   = "filemanager"
	projectConfig = "stg"
	
)

func FetchDopplerData() {
	// Construct the URL
	url := fmt.Sprintf(
		"https://api.doppler.com/v3/configs/config/secrets/download?project=%s&config=%s&format=json&include_dynamic_secrets=true&dynamic_secrets_ttl_sec=10",
		projectName, projectConfig,
	)

	// Create a new HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("failed to create request: %v", err)
	}

	// Add headers
	req.Header.Add("accept", "application/json")
	req.Header.Add("authorization", "Bearer "+os.Getenv("DOPPLER_TOKEN"))

	// Send the request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("failed to perform request: %v", err)
	}
	defer res.Body.Close()

	// Read the response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("failed to read response body: %v", err)
	}

	// Unmarshal the JSON response into a struct
	var data core.DopplerData
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Printf("failed to unmarshal response: %v", err)
	}

	_ = os.Setenv("MONGODB_CONNECTION", data.MONGODB)

}
