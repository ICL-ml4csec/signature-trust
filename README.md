# Commit Verification Tool

Verify that **every commit on your branch and in your third‑party dependencies** has a valid cryptographic signature with comprehensive policy enforcement and structured reporting.

## Signed Commits Required

**This repository requires all commits to be cryptographically signed.** 

**[Setup Guide →](SETUP_SIGNING.md)** | Supports GPG & SSH signing

---

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

**Policy Format:** `expired:email-mismatch:uncertified:missingkey:github-automated:unsigned:unregistered` (true/false for each)

### Examples

```bash
export GITHUB_TOKEN="ghp_yourTokenHere"

# Check last 6 months with strict dependency policy
go run ./main.go ICL-ml4csec/signature-trust main "$GITHUB_TOKEN" all "6 months" "1 week" \
  "false:false:false:false:true:false:false" \
  "true:true:true:true:true:false:false"

# Generate JSON report with 1 year time-range
go run ./main.go ICL-ml4csec/signature-trust main "$GITHUB_TOKEN" all "1 year" "30 days" \
  "false:false:false:false:true:false:false" \
  "true:true:true:true:true:false:false" \
  json security-report.json

# Short format with relaxed policies
go run ./main.go ICL-ml4csec/signature-trust main "$GITHUB_TOKEN" all "3m" "1w" \
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
Signature Check Summary (ICL-ml4csec/signature-trust):
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
Use this tool as a GitHub Action to automatically verify signatures in your CI/CD pipeline.

### Basic Usage
Create `.github/workflows/signature-verification.yml`:

```yaml
name: Signature Verification

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  verify-signatures:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set branch name
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            echo "BRANCH_NAME=${{ github.head_ref }}" >> $GITHUB_ENV
          else
            echo "BRANCH_NAME=${{ github.ref_name }}" >> $GITHUB_ENV
          fi

      - name: Verify Signatures
        uses: ICL-ml4csec/signature-trust@v1.1.4
        with:
          repository: ${{ github.repository }}
          branch: ${{ env.BRANCH_NAME }}
          token: ${{ secrets.GITHUB_TOKEN }}
          repo-policy: "false:false:false:false:true:false:false"
          deps-policy: "true:true:true:true:true:false:false"

      - name: Upload verification report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: signature-verification-report
          path: signature-report.json

```

### Advanced Configuration

```yaml
- name: Strict Security Verification
  uses: ICL-ml4csec/signature-trust@v1.1.4
  with:
    repository: ${{ github.repository }}
    branch: ${{ env.BRANCH_NAME }}
    token: ${{ secrets.GITHUB_TOKEN }}
    commits-to-check: "50"
    time-range: "3 months"
    key-age-period: "1 week"
    repo-policy: "false:false:false:false:true:false:false"
    deps-policy: "false:false:false:false:true:false:false"
    output-format: "json"
    output-file: "security-report.json"
```

### Integration with Merge Protection

Enable "Require status checks to pass before merging" in your repository settings and select the signature verification job to prevent merging unsigned commits.

## Policy Configuration

Configure signature acceptance policies with seven boolean flags:

1. **expired**: Accept valid signatures made with expired keys (valid-but-expired-key)

2. **email-mismatch**: Accept signatures where signer email != commit author (signed-but-untrusted-email)

3. **uncertified**: Accept signatures valid but not certified (valid-but-not-certified)

4. **missingkey**: Accept when the public key isn't available (signed-but-missing-key)

5. **github-automated**: Accept GitHub's automated commit signatures (github-automated-signature)

6. **unsigned**: Accept commits without any signature (unsigned)

7. **unregistered**: Accept valid signatures made with keys not linked to the author’s GitHub account (valid-but-key-not-on-github)


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


## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details