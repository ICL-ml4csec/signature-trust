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

 <!-- ### Running with Docker

```bash
# 1. Build the image
docker build -t commit-verifier .

# 2. Scan a repo (replace the placeholders)
docker run --rm commit-verifier <owner/repo> <branch> <PAT>
```
All dependencies are already in the image; no Go installation required on the host. -->



<!-- 
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
   * `AcceptEmailMismatches`: true/false
   * `AcceptUncertifiedSigner`: true/false
   * `AcceptMissingPublicKey`: true/false

2. Parse `go.mod`, `requirements.txt`, and `package.json` (if present), resolve each dependency’s tag → commit SHA, then print the percentage of signed commits for the most recent `n` commits on that SHA’s branch.

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


## Next Steps
* Evaluate on a set of open-source repositories.

 -->


# Commit Verification Tool

Verify that **every commit on your branch and in your third‑party dependencies** has a valid cryptographic signature with comprehensive policy enforcement and structured reporting.

## Quick‑Start

> **Personal Access Token (PAT)**: Generate one at **Settings → Developer settings → Personal access tokens → Tokens (classic)**. The token only needs `repo` → `public_repo` (public) or `repo` (private) scope so that the API can list commits and tags.

### Using the CLI

Requires Go ≥ 1.23 and a Personal Access Token (PAT).

```bash 
go run ./main.go <owner/repo> <branch> <PAT> <commits> <time-period> <key-age-period> <repo-policy> <deps-policy> [output-format] [output-file]
```

**Parameters:**
- `<commits>`: Number of commits to check or "all"
- `<time-period>`: Human-readable time range (e.g., "3 months", "1 year", "30 days", "" for no limit)
- `<key-age-period>`: Minimum key age (e.g., "1 week", "30 days", "1 month")

- `<repo-policy>`: Policy for repository commits (format below)  
  _Note: `unsigned` is always treated as `false` — repository commits **must** be signed. `github-automated` is always treated as `true`. All commits are checked regardless of the time period; the time filter only applies to dependencies._

- `<deps-policy>`: Policy for dependency commits (format below)
- `[output-format]`: "console" (default) or "json"
- `[output-file]`: Path for JSON report (when using json format)

**Policy Format:** `expired:untrusted:uncertified:missingkey:github-automated:unsigned:unauthorized` (true/false for each)

### Examples

```bash
export GITHUB_TOKEN="ghp_yourTokenHere"

# Check last 6 months with strict dependency policy
go run ./main.go ICL-ml4csec/msc-hmj24 main "$GITHUB_TOKEN" all "6 months" "1 week" \
  "false:false:false:false:true:false:false" \
  "true:true:true:true:true:false:false"

# Generate JSON report with 1 year time-range
go run ./main.go ICL-ml4csec/msc-hmj24 main "$GITHUB_TOKEN" all "1 year" "30 days" \
  "false:false:false:false:true:false:false" \
  "true:true:true:true:true:false:false" \
  json security-report.json

# Short format with relaxed policies
go run ./main.go ICL-ml4csec/msc-hmj24 main "$GITHUB_TOKEN" all "3m" "1w" \
  "true:true:true:true:true:false:false" \
  "true:true:true:true:true:true:false"
```

## Time Period Formats

The tool supports intuitive time period specifications:

- **Days:** `"1 day"`, `"7 days"`, `"30 days"`, `"1d"`
- **Weeks:** `"1 week"`, `"2 weeks"`, `"1w"`
- **Months:** `"1 month"`, `"3 months"`, `"6 months"`, `"1m"`
- **Years:** `"1 year"`, `"2 years"`, `"5 years"`, `"1y"`
- **Custom:** `"45 days"`, `"18 months"`, `"2 years"`
- **No limit:** `""` (empty string)

## What the Tool Checks

### Repository Analysis
- **Commit Signature Verification**: Validates cryptographic signatures on repository commits
- **Unsigned commits always rejected**: Repository commits must be signed, regardless of policy flag
- **Time-based Filtering**: Analyzes all commits in the repository (full history, no time cutoff).
- **Policy Enforcement**: Configurable acceptance criteria for different signature types
- **Key Age Validation**: Ensure signing keys meet minimum age requirements

### Dependency Analysis
The tool automatically detects and analyzes dependencies from:
- **Go**: `go.mod` files
- **JavaScript/Node.js**: `package.json` files  
- **Python**: `requirements.txt` files

For each dependency, it:
1. Resolves package versions to specific Git commits
2. Verifies signatures on recent commits in the dependency
3. Applies the same policy framework as repository commits, can add time-based filtering
4. Reports security scores and policy violations

### Output Formats

**Console Output:**
- Summary statistics and security scores
- Detailed policy violation breakdowns
- Human-readable commit summaries with detailed rejection reasons

**JSON Output:**
- Structured data with complete commit analysis
- Policy configuration and time range metadata
- Suitable for integration with CI/CD systems and security dashboards

## Sample Output

```text
=== REPOSITORY SIGNATURE CHECK ===
Checking all commits for branch: main
Commits newer than 6 months (26 Feb 2025)
Key age policy: Signing keys must be older than 1 week

== RESULTS ==
Signature Check Summary (ICL-ml4csec/msc-hmj24):
    Total commits: 37
    Valid signatures: 30
    Policy Result: PASSED
       * Accepted: 37
       * Rejected: 0
    Security Score: 100%

=== THIRD-PARTY DEPENDENCIES CHECK ===
Checking all commits in third-party library:
     Manifest: go.mod
     Package: gorilla/mux Version: v1.8.0
     Commits newer than 6 months (26 Feb 2025)
     Key age policy: Signing keys must be older than 1 week

== RESULTS ==
Dependency gorilla/mux@v1.8.0: No relevant commits found that fit the criteria (skipped)

=== THIRD-PARTY DEPENDENCIES CHECK ===
Checking all commits in third-party library:
     Manifest: go.mod
     Package: stretchr/testify Version: v1.10.0
     Commits newer than 6 months (26 Feb 2025)
     Key age policy: Signing keys must be older than 1 week

== RESULTS ==
Signature Check Summary (stretchr/testify):
    Total commits: 22
    Valid signatures: 0
    Policy Result: FAILED
       * Accepted: 6
       * Rejected: 16
    Security Score: 27.3%

Policy-dependent rejections:
    - Unsigned commits: 16 commits
      * a53be35c3b0cfcd5189cffcfd75df60ea581104c: Unsigned commit rejected by policy
      * aafb604176db7e1f2c9810bc90d644291d057687: Unsigned commit rejected by policy
      * ... and 13 more (see JSON report for full details)

✅ Repository verification passed
❌ Dependency verification failed: 1 of 2 dependencies rejected by policy
```

## GitHub Actions Integration

Create `.github/workflows/signature-verification.yml`:

```yaml
name: Signature Verification

on:
  pull_request:
    types: [opened, synchronize]
  push:
    branches: [main, develop]

jobs:
  verify-signatures:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
        
    - uses: actions/setup-go@v4
      with:
        go-version: '1.21'
        
    - name: Verify Signatures
      run: |
        go run ./main.go ${{ github.repository }} ${{ github.ref_name }} ${{ secrets.GITHUB_TOKEN }} \
          all "6 months" "1 week" \
          "false:false:false:false:true:false:false" \
          "true:true:true:true:true:false:false" \
          json signature-report.json
          
    - uses: actions/upload-artifact@v3
      if: always()
      with:
        name: signature-report
        path: signature-report.json
```

## Policy Configuration

Configure signature acceptance policies with seven boolean flags:

1. **expired**: Accept signatures that are cryptographically valid but made with expired keys (valid-but-expired-key)

2. **untrusted**: Accept signatures where the signer's email does not match the commit author (signed-but-untrusted-email)

3. **uncertified**: Accept signatures made with uncertified keys — valid but not certified by a trusted authority (valid-but-not-certified)

4. **missingkey**: Accept signatures when the commit is signed but the public key is not available for verification (signed-but-missing-key)

5. **github-automated**: Accept GitHub's automated commit signatures, such as those from web UI merges (github-automated-signature)

6. **unsigned**: Accept commits that are not signed at all (unsigned)

7. **unauthorized**: Accept signatures that are valid but made with a key not linked to the author’s GitHub account (valid-but-key-not-on-github)

**Example Policies:**

```bash
# Strict security (production)
"false:false:false:false:true:false:false"

# Balanced
"true:true:true:true:true:false:false"

# Permissive
"true:true:true:true:true:true:false"
```

## Exit Codes

- **0**: All signature checks passed
- **1**: Signature verification failed (repository or dependencies)

Perfect for CI/CD integration and merge protection rules.

## Architecture

- **Modular parsers**: Support for different package managers
- **Policy enforcement**: Flexible, configurable security policies
- **Time-aware analysis**: Focus on recent commits and key activity
- **Structured output**: Human-readable output and machine-readable JSON for automation
