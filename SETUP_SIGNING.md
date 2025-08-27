# Git Commit Signing Setup Guide

This guide helps you set up commit signing to verify your identity on GitHub. You can choose between **GPG** (traditional, more features) or **SSH** (simpler if you already use SSH).

## Quick Start: Enable Signing by Default

Once you've set up your keys (below), configure Git to sign all commits automatically:

```bash
git config --global commit.gpgsign true
```

To skip signing on a specific commit:
```bash
git commit --no-gpg-sign
```

---

## Option 1: GPG Commit Signing

### Step 1: Install GPG

- **macOS**: `brew install gnupg`
- **Ubuntu**: `sudo apt install gnupg`
- **Windows**: Install [Gpg4win](https://www.gpg4win.org/)

### Step 2: Generate Your GPG Key

```bash
gpg --full-generate-key
```

When prompted:
- **Key type**: RSA and RSA
- **Key size**: 4096
- **Expiry**: 1 year (recommended)
- **Name**: Your real name
- **Email**: Same email as your GitHub account
- **Passphrase**: Choose something secure

### Step 3: Find Your Key ID

```bash
gpg --list-secret-keys --keyid-format=long
```

Look for a line like: `sec rsa4096/ABCD1234EFGH5678`  
Copy the part after the slash: `ABCD1234EFGH5678`

### Step 4: Configure Git

```bash
git config --global user.signingkey ABCD1234EFGH5678
git config --global commit.gpgsign true
```

### Step 5: Export and Add to GitHub

Export your public key:
```bash
gpg --armor --export ABCD1234EFGH5678
```

Copy the entire output (including `-----BEGIN PGP PUBLIC KEY BLOCK-----` and `-----END PGP PUBLIC KEY BLOCK-----`).

Then:
1. Go to GitHub → **Settings** → **SSH and GPG keys**
2. Click **New GPG key**
3. Paste your exported key
4. Save

### Step 6: Fix Common Issues

If you see errors like "Inappropriate ioctl for device" or "No pinentry":

**Add to your shell config** (`~/.zshrc`, `~/.bashrc`, etc.):
```bash
export GPG_TTY=$(tty)
```

Then reload: `source ~/.zshrc`

**Install pinentry**:
- **Ubuntu**: `sudo apt install pinentry-curses`
- **macOS**: Usually included with `brew install gnupg`
- **Windows**: Included with Gpg4win

**Optional: Force terminal-based prompts**

Edit `~/.gnupg/gpg-agent.conf`:
```bash
pinentry-program /usr/bin/pinentry-curses
```

Adjust path as needed:
- macOS (Homebrew): `/opt/homebrew/bin/pinentry-mac`
- Ubuntu: `/usr/bin/pinentry-tty` or `/usr/bin/pinentry-curses`

Then restart GPG agent:
```bash
gpgconf --kill gpg-agent
```

### Step 7: Test Your Setup

```bash
git commit -S -m "Test signed commit"
```

Check GitHub - you should see a "Verified" badge!

### Optional: Cache Your Passphrase

To avoid entering your passphrase constantly, edit `~/.gnupg/gpg-agent.conf`:

```bash
default-cache-ttl 604800
max-cache-ttl 604800
```

This caches for 1 week (604800 seconds). Adjust as needed:
- 1 hour: 3600
- 1 day: 86400

Restart the agent: `gpgconf --kill gpg-agent`

---

## Option 2: SSH Commit Signing

### Step 1: Choose Your Approach

**Option A**: Use an existing SSH key  
**Option B**: Generate a dedicated signing key

### Step 2A: Using an Existing SSH Key

If you already have `~/.ssh/id_ed25519`:

1. **Display your public key**:
   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. **Add to GitHub as signing key**:
   - Go to GitHub → **Settings** → **SSH and GPG keys**
   - Click **New SSH Key**
   - Set **Key Type** to **Signing Key**
   - Paste and save

3. **Configure Git**:
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519.pub
   git config --global commit.gpgsign true
   ```

### Step 2B: Generate a Dedicated Signing Key

```bash
ssh-keygen -t ed25519 -C "your_email@example.com" -f ~/.ssh/id_ed25519_signing
```

Then:
1. **Add public key to GitHub**:
   ```bash
   cat ~/.ssh/id_ed25519_signing.pub
   ```
   Add this to GitHub as a **Signing Key**

2. **Configure Git**:
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
   git config --global commit.gpgsign true
   ```

3. **Optional: Load into SSH agent**:
   ```bash
   ssh-add ~/.ssh/id_ed25519_signing
   ```

### Step 3: Test Your Setup

```bash
git commit -S -m "SSH-signed commit"
```

Verify locally:
```bash
git log --show-signature
```

---

## Maintenance

### Extending GPG Key Expiration

When your GPG key nears expiration:

1. **List keys**:
   ```bash
   gpg --list-keys --keyid-format=long
   ```

2. **Edit the key**:
   ```bash
   gpg --edit-key ABCD1234EFGH5678
   ```

3. **In the GPG prompt**:
   ```
   expire
   ```
   Choose new expiration (e.g., `1y` for 1 year, `0` for never)

4. **Update subkeys**:
   ```
   key 1
   expire
   ```
   Set same expiration

5. **Save**:
   ```
   save
   ```

6. **Optional: Re-export to GitHub**:
   ```bash
   gpg --armor --export ABCD1234EFGH5678
   ```

### Troubleshooting

**"gpg: signing failed"**:
- Check `export GPG_TTY=$(tty)` is in your shell config
- Install pinentry: `sudo apt install pinentry-curses`
- Restart GPG agent: `gpgconf --kill gpg-agent`

**SSH signing not working**:
- Verify key is added as **Signing Key** (not just Authentication)
- Check Git config: `git config --list | grep signing`
- Load key into agent: `ssh-add ~/.ssh/your_key`

**Commits not showing as verified**:
- Email in Git config must match GitHub account
- Key must be added to the correct GitHub account
- For GPG: check key isn't expired