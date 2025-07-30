package client

import (
	"net/http"
)

func DoGet(url string, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorisation", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	return client.Do(req)
}
