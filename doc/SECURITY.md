# Security Guide

## Overview

This guide covers security considerations for using the Spotify to Tidal Playlist Transfer Tool.

**IMPORTANT**: This tool is designed for personal use. Do not use it in production environments without implementing proper security measures.

## Credential Management

### Environment Variables (Recommended)

**DO**:
```bash
# Store in shell profile
export SPOTIFY_CLIENT_ID='your_id'
export SPOTIFY_CLIENT_SECRET='your_secret'
```

**DON'T**:
```python
# Never hardcode in script
SPOTIFY_CLIENT_ID = "abc123def456"  # ❌ WRONG
```

### Secure Storage Options

For enhanced security, consider:

1. **Password Managers**
   - 1Password
   - LastPass
   - Bitwarden
   - Store credentials in secure vault

2. **Operating System Keychains**
   ```python
   # macOS Keychain example
   import keyring
   client_id = keyring.get_password("spotify", "client_id")
   ```

3. **Environment Variable Managers**
   - direnv (auto-loads per directory)
   - dotenv files with restricted permissions

### Never Commit Credentials

**Add to .gitignore**:
```gitignore
# Credentials
.env
.env.local
config.json
*_credentials.json

# Session files
.spotify_tidal_config/
```

**Check for leaks**:
```bash
# Before committing
git diff | grep -i "client"
git diff | grep -i "secret"
```

## Session Storage

### Current Implementation

The tool stores session tokens in:
```
~/.spotify_tidal_config/
├── spotify_session.json
└── tidal_session.json
```

### Security Measures Implemented

1. **File Permissions**
   - Directory: `0700` (rwx------)
   - Files: `0600` (rw-------)
   - Only owner can read/write

2. **Atomic Writes**
   - Writes to temp file first
   - Atomic rename prevents corruption
   - Reduces risk of partial writes

3. **Basic Obfuscation**
   - XOR cipher with SHA-256 key derivation
   - **NOT cryptographically secure**
   - Prevents casual inspection only

### Security Limitations

**WARNING**: Current session storage is NOT secure against:
- Determined attackers
- Malware with user-level access
- System administrators
- Forensic analysis

### Recommendations for Enhanced Security

#### Option 1: Use System Keychain

```python
import keyring

# Store
keyring.set_password("spotify-tidal", "spotify_token", json.dumps(token_data))

# Retrieve
token_data = json.loads(keyring.get_password("spotify-tidal", "spotify_token"))
```

#### Option 2: Implement Proper Encryption

```python
from cryptography.fernet import Fernet

# Generate key once, store securely
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt
encrypted = cipher.encrypt(json.dumps(data).encode())

# Decrypt
decrypted = json.loads(cipher.decrypt(encrypted).decode())
```

Install:
```bash
pip install cryptography
```

#### Option 3: Don't Store Sessions

Comment out session saving for maximum security:
```python
# Disable in script.py
# self.session_manager.save_spotify_session(...)
# self.session_manager.save_tidal_session(...)
```

**Trade-off**: Must re-authenticate every run.

## API Token Security

### Spotify Tokens

**Scope**: The tool requests minimal scopes:
- `playlist-read-private`
- `playlist-read-collaborative`
- `user-library-read`

**What it CANNOT do**:
- ❌ Modify your Spotify playlists
- ❌ Delete tracks
- ❌ Access premium features
- ❌ Make purchases
- ❌ Change account settings

**Token Lifetime**: ~1 hour (with refresh token for re-authentication)

### Tidal Tokens

**Access Level**: Full account access through OAuth

**What it CAN do**:
- ✅ Create playlists
- ✅ Add tracks
- ✅ Read account info

**Token Lifetime**: Varies by session

### Revoking Access

#### Revoke Spotify Access

1. Go to [Spotify Account Settings](https://www.spotify.com/account/apps/)
2. Find "Playlist Transfer Tool" (or your app name)
3. Click "Remove Access"

#### Revoke Tidal Access

1. Go to Tidal account settings
2. Navigate to "Authorized Applications"
3. Revoke access to the tool

## Network Security

### HTTPS Only

The tool uses HTTPS for all API communications:
- Spotify API: `https://api.spotify.com`
- Tidal API: `https://api.tidal.com`

### OAuth Redirect Security

**Redirect URI**: `http://127.0.0.1:8080`

**Why HTTP**:
- Localhost only (not exposed to internet)
- Temporary redirect server
- Industry standard for OAuth desktop apps

**Security Notes**:
- Only listens on localhost (127.0.0.1)
- Server stops after redirect
- No data transmitted over insecure network

## Code Security

### Dependencies

Regularly update dependencies for security patches:

```bash
pip install --upgrade -r requirements.txt
```

### Vulnerability Scanning

Check for known vulnerabilities:

```bash
pip install safety
safety check
```

Or use:
```bash
pip-audit
```

## Privacy Considerations

### Data Collection

**What the tool accesses**:
- Your Spotify playlist names and track metadata
- Your Tidal account (for playlist creation)

**What it does NOT do**:
- ❌ Track your listening habits
- ❌ Send data to third parties
- ❌ Store credentials remotely
- ❌ Upload playlists anywhere
- ❌ Analytics or telemetry

### Local Processing

All processing happens locally on your machine:
- No cloud services involved
- No remote logging
- No data leaving your computer (except API calls)

### Missing Tracks File

The `missing_tracks_*.txt` file contains:
- Track names
- Artist names
- Album names

**Privacy Note**: This file is created locally and contains your playlist data. Delete after use if concerned about privacy.

## Multi-User Environments

### Shared Computers

**Security Risks**:
- Other users can read `~/.spotify_tidal_config/`
- Environment variables may be visible

**Mitigation**:
```bash
# After each use
rm -rf ~/.spotify_tidal_config/
unset SPOTIFY_CLIENT_ID
unset SPOTIFY_CLIENT_SECRET
```

### Public/Work Computers

**DO NOT USE on**:
- Public libraries
- Internet cafes
- Work computers (without permission)
- Shared lab computers

**Why**: Credentials and sessions may persist or be logged.

## Best Practices

### 1. Minimize Credential Exposure

```bash
# Use credential file with restricted permissions
cat > ~/.spotify_credentials
SPOTIFY_CLIENT_ID=xxx
SPOTIFY_CLIENT_SECRET=yyy
# Press Ctrl+D

chmod 600 ~/.spotify_credentials
source ~/.spotify_credentials
```

### 2. Regular Cleanup

```bash
# Weekly cleanup script
#!/bin/bash
rm -rf ~/.spotify_tidal_config/
find . -name "missing_tracks_*.txt" -mtime +7 -delete
```

### 3. Audit Access

Regularly review:
- [Spotify authorized apps](https://www.spotify.com/account/apps/)
- Tidal authorized applications
- Remove unused apps

### 4. Monitor for Unusual Activity

Check for:
- Unexpected playlists created
- Unknown devices logged in
- Unusual API usage

### 5. Use Separate Developer App

Create a dedicated Spotify app for this tool:
- Easier to revoke access
- Doesn't affect other integrations
- Better audit trail

## Incident Response

### If Credentials Are Compromised

1. **Immediately revoke API access** (see Revoking Access section)
2. **Generate new credentials** from Spotify Developer Dashboard
3. **Update environment variables** with new credentials
4. **Check for unauthorized activity** in both accounts
5. **Change passwords** if account compromise suspected

### If Session Files Are Exposed

1. **Delete session files**:
   ```bash
   rm -rf ~/.spotify_tidal_config/
   ```

2. **Revoke API access** from both services

3. **Re-authenticate** next time you use the tool

### If Repository Is Public

**If you accidentally committed credentials**:

```bash
# Remove from git history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch script.py" \
  --prune-empty --tag-name-filter cat -- --all

# Force push
git push origin --force --all

# Immediately revoke and regenerate credentials
```

**Better**: Use tools like [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)

## Security Checklist

Before each use:

- [ ] Credentials stored as environment variables
- [ ] Not using shared/public computer
- [ ] Latest version of script
- [ ] Dependencies up to date
- [ ] `.gitignore` includes session files
- [ ] No hardcoded credentials in code

After each use:

- [ ] Review created playlists
- [ ] Delete missing tracks file (if contains sensitive data)
- [ ] Clear sessions on shared computers
- [ ] Unset environment variables on shared computers

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. Email maintainers privately
3. Provide details:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Legal and Compliance

### Terms of Service

Ensure compliance with:
- [Spotify Developer Terms](https://developer.spotify.com/terms)
- [Tidal Terms of Service](https://tidal.com/terms)

### Personal Use Only

This tool is for personal use only:
- ❌ Don't use commercially
- ❌ Don't redistribute with hardcoded credentials
- ❌ Don't scrape or store user data
- ❌ Don't exceed API rate limits

## Future Security Enhancements

Planned improvements:
- Proper encryption for session storage
- System keychain integration
- OAuth token refresh improvements
- Security audit logging
- Credential rotation support

## Resources

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Spotify Developer Policy](https://developer.spotify.com/policy)

## Next Steps

- See [INSTALLATION.md](INSTALLATION.md) for setup
- See [USAGE.md](USAGE.md) for usage instructions
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues
