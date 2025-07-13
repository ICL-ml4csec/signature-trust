<!-- ## Commit Verification Tool

Use locally:
- Make sure you have a personal access token, Settings -> Developer Settings -> personal access tokens -> generate new token (classic).
- Clone the repository. 
- can run main with three arguments, repository (username/repository), branch, token
or act push? (do i need to do something/install something for this to work?)


Current tool:
- Checks current branch in repository to and output is percentage of verified commits on branch
- Parses go.mod file, finds package and version and finds % verified commits through APIs, 30 commits per page
- Parses requirements.txt file, finds package and version and finds % verified commits through APIs, 30 commits per page

Next steps:
- Handle more cases of manifest files, as well as more edge cases for current manifest file parsing. 
- Add adjustable trust policies
- Test on evaluation repositories
 -->

 <!-- This repo ships both **a GitHub Action** and **a standalone CLI/Docker image** that run the exact same logic. Clone it, use it in CI, or dry‑run the workflow locally with [`act`](https://github.com/nektos/act) – whatever suits your workflow. -->
<!-- | Scenario             | Command / File                                                                                       | Notes                                                     |
| -------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **GitHub**           | Add `.github/workflows/commitverification.yml` (already in this repo)                                | Every push / PR gets scanned automatically.               |
| **Local (Go)**       | `go run ./main.go <owner/repo> <branch> <PAT>`                                                       | Requires Go ≥ 1.23 and a Personal Access Token (PAT).     |
| **Local (Docker)**   | `docker build -t commit‑verifier .`<br> <br>`docker run --rm commit‑verifier <owner/repo> <branch> <PAT>` | Runs entirely in Docker, no local Go install required.                                 |
| **Dry‑run workflow** | `act push`                                                                                           | Simulates the GitHub Action locally. Install `act` first. | -->


<!-- > **Tip for `docker buildx` users** – if your Docker CLI defaults to Buildx, make sure you still pass the build context (`.`) just like above: `docker buildx build -t commit-verifier .`.  Omitting the dot will trigger the *"requires exactly 1 argument"* error.

All dependencies are vendored inside the image; *no* Go toolchain is required on the host. -->


<!-- ## Why is there a workflow file in the repo?

Keeping `.github/workflows/commitverification.yml` in the repository **doesn’t interfere** with local usage – Git simply treats it like any other file.  When you clone the repo, the file just lives on disk; it only becomes active when the repository is pushed to GitHub and Actions are enabled.  Feel free to ignore or delete it in downstream forks if you don’t need the Action.

--- -->



# Commit Verification Tool

Verify that **every commit on your branch and in your third‑party dependencies** has a valid cryptographic signature.


## Quick‑Start


> **Personal Access Token (PAT)**: Generate one at **Settings → Developer settings → Personal access tokens → Tokens (classic)**. The token only needs `repo` → `public_repo` (public) or `repo` (private) scope so that the API can list commits and tags.


### Using the CLI directly
Requires Go ≥ 1.23 and a Personal Access Token (PAT).
```bash 
go run ./main.go <owner/repo> <branch> <PAT> <commits> <expired> <untrusted> <uncertified> <missingkey>
```

Example:
```bash
export GITHUB_TOKEN="ghp_yourTokenHere"

go run ./main.go ICL-ml4csec/msc-hmj24 main "$GITHUB_TOKEN" 30 true false false true
```

The program will

1. Fetch the last `n` commits on the target branch and print the percentage that are signed according to GitHub API and local validation. Local checks factor in user-defined trust configuration:

   * `CommitsToCheck`: number of commits to check (e.g. 30 or "all")
   * `AcceptExpiredKeys`: true/false
   * `AcceptUntrustedSigners`: true/false
   * `AcceptUncertifiedKeys`: true/false
   * `AcceptMissingPublicKey`: true/false

2. Parse `go.mod`, `requirements.txt`, and `package.json` (if present), resolve each dependency’s tag → commit SHA, then print the percentage of signed commits for the most recent `n` commits on that SHA’s branch.

<!-- ### Running with Docker

```bash
# 1. Build the image
docker build -t commit-verifier .

# 2. Scan a repo (replace the placeholders)
docker run --rm commit-verifier <owner/repo> <branch> <PAT>
```
All dependencies are already in the image; no Go installation required on the host. -->

### Dry-run the workflow:
```bash
 act push 
```
(requires [`act`](https://github.com/nektos/act)).


## Sample output

```text
Checking commits for repository: ICL-ml4csec/msc-hmj24 on branch: development
Verified commits: 100.00% (5 out of 5)

Checking commits locally for repository: ICL-ml4csec/msc-hmj24 on branch: development
Successfully imported SSH key(s) from https://github.com/ICL-ml4csec.keys
Successfully imported GPG key(s) from https://github.com/ICL-ml4csec.gpg
Results from Local:
Commit 8a90de8abf5e8a0b3ec36bf30498e209df65d7a3 status: valid-but-not-certified
Output:
commit 8a90de8abf5e8a0b3ec36bf30498e209df65d7a3
gpg: Signature made Sat Jul 12 14:56:34 2025 GMT
gpg:                using RSA key B5690EEEBB952194
gpg: Good signature from "GitHub <noreply@github.com>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 9684 79A1 AFF9 27E3 7D1A  566B B569 0EEE BB95 2194
Merge: f96f53e 5775011
Author: Hanna Margrét Jónsdóttir <121580397+hannajonsd@users.noreply.github.com>
Date:   Sat Jul 12 15:56:34 2025 +0100

    Merge pull request #6 from ICL-ml4csec/feature/verify-signatures-locally
    
    Feature/verify signatures locally


Verified commit 5775011901c7d15df3fddd14eb2da3b365f53c2d status: valid

Verified commit 74e31bbcd4ed664547da6064fa9e52fb7328c030 status: valid

Verified commit 6ebea3afb7c627e19444d7f0d97926f448f7c2d4 status: valid

Verified commit f96f53e002c5150355c655dcc9e68eca16e6d7d9 status: valid

Local verified commits: 80.00%

Manifest: requirements.txt
Package: httpx Version: 0.27.2
Repository URL: encode/httpx
Verified commits: 100.00% (5 out of 5)

Manifest: package.json (dependencies)
Package: left-pad Version: 1.3.0
Repository URL: stevemao/left-pad
Verified commits: 40.00% (2 out of 5)
```


## What the tool checks today

**Commit Verification:** 
* **GitHub API validation**:
  * Checks if commits are verified via the **GitHub API** (`commit.verification.verified` field).
  * Uses pagination to fetch `n` commits (user-defined).
* **Local Git validation**:
  * Clones the target repository to a temp directory.
  * Uses `git rev-list` and `git log --show-signature` for detailed signature info.
  * Automatically fetches missing GPG and SSH keys from GitHub.
  * Respects user-specified trust policy flags.
  * Outputs signed commit percentage and detailed status (valid, unsigned, expired, etc.).
    * If a commit does not meet user-defined criteria the full signature is printed

<!-- 
* **`go.mod`** – For each Go module:
  * Extracts the module path and version.
  * Resolves the tag to the corresponding Git commit SHA.
  * Retrieves the n last commits (based on user input) on that commit’s branch.
  * Calculates the percentage of commits signed with GPG or SSH.

* **`requirements.txt`** - For each Python package:
  * Parses the package name and version (or falls back to the latest).
  * Retrieves metadata from the PyPI registry.
  * Extracts and normalises the GitHub repository URL.
  * Resolves the tag to the corresponding Git commit SHA.
  * Retrieves the n last commits (based on user input) on that commit’s branch.
  * Calculates the percentage of commits signed with GPG or SSH.

* **`package.json`** - For each npm package in dependencies and devDependencies:
  * Handles all common formats: exact versions, semver ranges (`^`, `~`, `*`, `x`, `-`), GitHub shorthands, Git URLs, scoped aliases (`npm:@scope/pkg@version`), and tags like `latest`.
  * Retrieves metadata from the npm registry.
  * Extracts and normalises the GitHub repository URL.
  * Resolves the tag to the corresponding Git commit SHA.
  * Retrieves the n last commits (based on user input) on that commit’s branch.
  * Calculates the percentage of commits signed with GPG or SSH.
 -->

## Next Steps
* Introduce more configurable trust policies (e.g. type of key).
* Decide on final output
* Refactor code for modularity and clarity
* Write unit tests
* Evaluate on a set of open-source repositories.
