# Security Guide

## Credential Management

**DO**: Use environment variables
```bash
export SPOTIFY_CLIENT_ID='your_id'
export SPOTIFY_CLIENT_SECRET='your_secret'
```

**DON'T**: Hardcode in script or commit to git

### Secure Storage Options

- Password managers (1Password, Bitwarden)
- OS keychains (`keyring` Python package)
- Restricted dotenv files (`chmod 600 .env`)

## Session Storage

Sessions stored in `~/.spotify_tidal_config/`:
- Directory permissions: `0700`
- File permissions: `0600`
- Uses XOR obfuscation (NOT cryptographically secure)

**Warning**: Current storage protects against casual inspection only, not determined attackers.

### Enhanced Security Options

```python
# Option 1: System keychain
import keyring
keyring.set_password("spotify-tidal", "token", json.dumps(data))

# Option 2: Proper encryption
from cryptography.fernet import Fernet
cipher = Fernet(key)
encrypted = cipher.encrypt(data.encode())
```

## API Tokens

### Spotify Scopes (read-only)
- `playlist-read-private`
- `playlist-read-collaborative`
- `user-library-read`

Cannot modify playlists, delete tracks, or access premium features.

### Tidal
Full account access via OAuth. Can create playlists and add tracks.

### Revoking Access
- **Spotify**: [Account Settings > Apps](https://www.spotify.com/account/apps/)
- **Tidal**: Account settings > Authorized Applications

## Best Practices

1. Never commit credentials to git
2. Use dedicated Spotify Developer App for this tool
3. Regularly review authorized apps in both services
4. Clear sessions on shared computers: `rm -rf ~/.spotify_tidal_config/`
5. Update dependencies regularly: `pip install --upgrade -r requirements.txt`

## If Compromised

1. Revoke API access immediately (see links above)
2. Generate new Spotify Developer credentials
3. Delete session files
4. Change passwords if account compromise suspected
