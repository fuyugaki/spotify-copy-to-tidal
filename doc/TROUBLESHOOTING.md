# Troubleshooting Guide

## Authentication

### Spotify Authentication Fails

| Cause | Solution |
|-------|----------|
| Invalid credentials | Verify env vars: `echo $SPOTIFY_CLIENT_ID` |
| Wrong redirect URI | Set exactly `http://127.0.0.1:8080` in Spotify Dashboard |
| Port in use | `lsof -i :8080` to check, kill process or use different port |
| Browser not opening | Copy URL from terminal and open manually |

### Tidal Authentication Fails

| Cause | Solution |
|-------|----------|
| Browser cache | Clear cookies for tidal.com |
| Stale session | `rm ~/.spotify_tidal_config/tidal_session.json` |
| Subscription issue | Verify Tidal subscription is active |
| Network/VPN | Temporarily disable VPN |

### Session Expired

Sessions last 24 hours. Clear and re-authenticate:
```bash
rm -rf ~/.spotify_tidal_config/
python3 script.py
```

## Transfer Issues

### Low Match Rate (<50%)

- **Content not on Tidal**: Some artists/labels aren't available
- **CJK tracks**: Expected 40-60% rate due to romanization differences
- **Regional restrictions**: Some content is region-locked

**Solutions**:
1. Lower thresholds in script.py:
   ```python
   self.match_threshold = 75  # Was 80
   self.cjk_match_threshold = 65  # Was 70
   ```
2. Check `missing_tracks_*.txt` for manual search suggestions

### Rate Limiting (429 errors)

```python
# Increase delay in script.py
self.rate_limiter = RateLimiter(base_delay=0.5)  # Was 0.2
```

Or wait 5-10 minutes and retry.

### Playlist Creation Fails

- Check Tidal account can create playlists manually
- Try simpler playlist name (avoid special characters)
- Check account tier limits

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `ModuleNotFoundError` | Missing deps | `pip install -r requirements.txt` |
| `AttributeError: NoneType` | Auth failed | Clear sessions, re-authenticate |
| `ConnectionError` | Network issue | Check internet, disable VPN |
| `JSONDecodeError` | Corrupt session | `rm -rf ~/.spotify_tidal_config/` |

## Platform-Specific

### Linux
```bash
# Permission denied on config dir
chmod 755 ~
mkdir -p ~/.spotify_tidal_config
chmod 700 ~/.spotify_tidal_config
```

### macOS
```bash
# SSL certificate error
/Applications/Python\ 3.x/Install\ Certificates.command
# or
pip install --upgrade certifi
```

### Windows
- Ensure default browser is set in Control Panel
- Use PowerShell profile for persistent env vars: `notepad $PROFILE`

## Debug Mode

Enable verbose logging:
```bash
python3 script.py -v transfer
```

Or set DEBUG level in script.py line 25:
```python
logging.basicConfig(level=logging.DEBUG, ...)
```
