package checksignature

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"

	"github.com/ICL-ml4csec/msc-hmj24/client"
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

func CheckSignature(repo string, branch string, token string, commitsToCheck int) {
	baseURL := fmt.Sprintf("https://api.github.com/repos/%s/commits", repo)
	total := 0.0
	verified := 0.0

	perPage := 100
	if commitsToCheck > 0 && commitsToCheck < 100 {
		perPage = commitsToCheck
	}

	page := 1
	fetched := 0

	for {
		query := url.Values{}
		query.Add("sha", branch)
		query.Add("per_page", strconv.Itoa(perPage))
		query.Add("page", strconv.Itoa(page))

		fullURL := fmt.Sprintf("%s?%s", baseURL, query.Encode())
		resp, err := client.DoGet(fullURL, token)
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

		for _, commit := range commits {
			total++
			fetched++
			if commit.Commit.Verification.Verified {
				verified++
			}
			if commitsToCheck > 0 && fetched >= commitsToCheck {
				break
			}
		}

		if len(commits) < perPage || (commitsToCheck > 0 && fetched >= commitsToCheck) {
			break
		}
		page++
	}

	if total == 0 {
		fmt.Println("No commits found.")
		return
	}

	percentage := (verified / total) * 100
	fmt.Printf("Verified commits: %.2f%% (%d out of %.0f)\n\n", percentage, int(verified), total)
}
