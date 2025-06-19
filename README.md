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
go run ./main.go <owner/repo> <branch> <PAT>
```

Example:
```bash
export GITHUB_TOKEN="ghp_yourTokenHere"

go run ./main.go ICL-ml4csec/msc-hmj24 main "$GITHUB_TOKEN"
```

The program will

1. Fetch the last 100 commits on the target branch and print the percentage that are signed.
2. Parse `go.mod` and `requirements.txt` (if present), resolve each dependency’s tag → commit SHA, then print the percentage of signed commits for the most recent 30 commits on that SHA’s branch.


### Running with Docker

```bash
# 1. Build the image
docker build -t commit-verifier .

# 2. Scan a repo (replace the placeholders)
docker run --rm commit-verifier <owner/repo> <branch> <PAT>
```
All dependencies are already in the image; no Go installation required on the host.

### Dry-run the workflow:
```bash
 act push 
```
(requires [`act`](https://github.com/nektos/act)).


## Sample output

```text
Checking commits for repository: ICL-ml4csec/msc-hmj24 on branch: feature/commit-check
Verified commits: 50.00%

Manifest: go.mod
Package: gorilla/mux v1.8.1
Repository URL: gorilla/mux
Verified commits: 93.33%

Fetching PyPI data for: https://pypi.org/pypi/tabulate/json
Manifest: requirements.txt
Package: tabulate 0.8.8
Repository URL: astanin/python-tabulate
Verified commits: 63.33%
```


## What the tool checks today

* **Repository commits:** Percentage of GPG/SSH‑signed commits for the last 100 commits on the target branch.
* **`go.mod`** – For each dependency:

  * Extracts the module path and version.
  * Resolves the corresponding tag → commit SHA.
  * Calculates the percentage of signed commits (last 30) on that commit’s branch.
* **`requirements.txt`** – Same flow for Python packages, using the PyPI API to locate their GitHub repo.


## Next Steps

* Parse additional manifest types (`package.json`, `cargo.toml`, `pom.xml`, …) and edge‑cases in existing parsers.
* Introduce configurable trust policies (e.g. min percentage required).
* Evaluate on a set of open-source repositories.

