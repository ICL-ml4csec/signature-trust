package checksignature

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hannajonsd/git-signature-test/client"
)

type GitCommitResponse struct {
	Commit struct {
		Author struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Date  string `json:"date"`
		} `json:"author"`
		Message      string `json:"message"`
		Verification struct {
			Verified bool   `json:"verified"`
			Reason   string `json:"reason"`
		} `json:"verification"`
	} `json:"commit"`
}

func CheckSignature(url string, token string) {
	resp, err := client.DoGet(url, token)
	if err != nil {
		fmt.Printf("Error fetching commits: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	var commits []GitCommitResponse
	if err := json.Unmarshal(body, &commits); err != nil {
		fmt.Printf("Error parsing commit JSON: %v\n", err)
		return
	}

	total := float64(len(commits))
	verified := 0.0

	for _, commit := range commits {
		if commit.Commit.Verification.Verified {
			verified++
		}
	}

	percentage := (verified / total) * 100
	fmt.Printf("Verified commits: %.2f%%\n", percentage)
}
