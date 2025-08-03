package client

import (
	"net/http"
)

// DoGet performs a GET request to the specified URL with authentication token
func DoGet(url string, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	return client.Do(req)
}
