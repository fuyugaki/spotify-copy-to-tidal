# Troubleshooting Guide

## Authentication Issues

### Spotify Authentication Fails

#### Problem: "Spotify authentication failed"

**Causes and Solutions**:

1. **Invalid Credentials**
   ```bash
   # Verify environment variables are set
   echo $SPOTIFY_CLIENT_ID
   echo $SPOTIFY_CLIENT_SECRET

   # If empty, set them again
   export SPOTIFY_CLIENT_ID='your_client_id'
   export SPOTIFY_CLIENT_SECRET='your_client_secret'
   ```

2. **Incorrect Redirect URI**
   - Go to [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
   - Select your app
   - Click "Edit Settings"
   - Ensure redirect URI is exactly: `http://127.0.0.1:8080`
   - Click "Save"

3. **Browser Not Opening**
   ```bash
   # Manually visit the authentication URL shown in the terminal
   # Copy the redirect URL from browser and paste into terminal
   ```

4. **Port Already in Use**
   ```bash
   # Check if port 8080 is in use
   lsof -i :8080  # Linux/macOS
   netstat -ano | findstr :8080  # Windows

   # Kill the process or use different port
   export SPOTIFY_REDIRECT_URI='http://127.0.0.1:8888'
   # Update in Spotify Dashboard too!
   ```

### Tidal Authentication Fails

#### Problem: "Tidal authentication failed after multiple attempts"

**Solutions**:

1. **Clear Browser Cache**
   - Clear cookies for `tidal.com`
   - Restart browser
   - Try authentication again

2. **Logout from Tidal**
   - Go to [tidal.com](https://tidal.com)
   - Sign out completely
   - Run script again
   - Sign in when prompted

3. **Clear Session Files**
   ```bash
   rm -rf ~/.spotify_tidal_config/tidal_session.json
   ```

4. **Check Tidal Subscription**
   - Ensure your Tidal subscription is active
   - Log in to Tidal web player to verify

5. **Try Different Browser**
   - Close all browser windows
   - Set default browser to Chrome/Firefox
   - Run script again

6. **Network Issues**
   ```bash
   # Test Tidal connectivity
   curl -I https://api.tidal.com

   # Check for proxy/VPN interference
   # Temporarily disable VPN and try again
   ```

### Session Expired

#### Problem: "Session expired, re-authentication required"

**Solution**: Sessions last 24 hours. Simply re-authenticate:

```bash
# Delete old sessions
rm -rf ~/.spotify_tidal_config/

# Run script
python3 script.py
```

## Transfer Issues

### Low Match Rate

#### Problem: "Success rate below 50%"

**Possible Causes**:

1. **Content Not Available on Tidal**
   - Some artists/labels aren't on Tidal
   - Regional restrictions
   - Exclusive content

2. **Playlist Contains Podcasts/Non-Music**
   - Tool only transfers music tracks
   - Filter playlist to music only

3. **Many Japanese/CJK Tracks**
   - CJK tracks have inherently lower match rates
   - This is normal behavior

**Solutions**:

1. **Lower Match Threshold** (for more matches, possible false positives)
   ```python
   # In script.py around line 496
   self.match_threshold = 75  # Was 80
   self.cjk_match_threshold = 65  # Was 70
   ```

2. **Check Missing Tracks File**
   - Review `missing_tracks_*.txt`
   - Manually search for tracks in Tidal
   - Some may be under different names/artists

3. **Verify Playlist Content**
   - Check if tracks exist on Tidal manually
   - Use Tidal search to verify availability

### Rate Limiting Errors

#### Problem: "429 Too Many Requests" or excessive delays

**Solutions**:

1. **Increase Base Delay**
   ```python
   # In script.py around line 501
   self.rate_limiter = RateLimiter(base_delay=0.5)  # Was 0.2
   ```

2. **Reduce Search Attempts**
   ```python
   # In script.py around line 640
   max_search_attempts = min(len(search_queries), 2)  # Was 4
   ```

3. **Wait and Retry**
   - Wait 5-10 minutes
   - Run script again
   - Tool will resume from where it left off (for playlists)

### Playlist Creation Fails

#### Problem: "Failed to create Tidal playlist"

**Solutions**:

1. **Check Tidal Permissions**
   - Ensure Tidal account can create playlists
   - Try creating a playlist manually in Tidal

2. **Check Playlist Name**
   - Special characters may cause issues
   - Try simpler playlist name

3. **Account Limits**
   - Some Tidal tiers have playlist limits
   - Check your account status

### Tracks Not Adding to Playlist

#### Problem: "Successfully added 0/50 tracks"

**Solutions**:

1. **Verify Track IDs**
   - Check that tracks were actually found
   - Review console output for "✓ Found" messages

2. **Retry with Smaller Batches**
   ```python
   # In script.py around line 777
   batch_size = 10  # Was 20
   ```

3. **Check Tidal API Status**
   - Visit [Tidal Status Page](https://status.tidal.com/)
   - API might be experiencing issues

## Performance Issues

### Slow Transfer Speed

#### Problem: "Transfer taking very long"

**Expected Times**:
- 50 tracks: 1-2 minutes
- 100 tracks: 3-5 minutes
- 200 tracks: 8-12 minutes
- 500 tracks: 20-30 minutes

**Optimization**:

1. **Reduce Search Attempts**
   ```python
   max_search_attempts = 2  # Was 4
   ```

2. **Reduce Search Results**
   ```python
   self.max_search_results = 10  # Was 15
   ```

3. **Increase Rate Limiter Aggressiveness** (risky)
   ```python
   self.rate_limiter = RateLimiter(base_delay=0.1)  # Was 0.2
   ```

### High Memory Usage

#### Problem: Script using too much memory

**Solution**: Process playlists in chunks (requires code modification)

Contact maintainers for batch processing feature request.

## Error Messages

### "ModuleNotFoundError: No module named 'X'"

**Solution**:
```bash
pip install -r requirements.txt --upgrade
```

### "AttributeError: 'NoneType' object has no attribute 'X'"

**Cause**: Authentication likely failed

**Solution**:
1. Check authentication completed successfully
2. Clear session files
3. Re-run script

### "ConnectionError" or "Timeout"

**Solutions**:

1. **Check Internet Connection**
   ```bash
   ping google.com
   ```

2. **Check Firewall**
   - Ensure Python/script can access internet
   - Temporarily disable firewall to test

3. **Proxy Issues**
   ```bash
   # If behind proxy, set:
   export HTTP_PROXY='http://proxy:port'
   export HTTPS_PROXY='http://proxy:port'
   ```

4. **DNS Issues**
   ```bash
   # Try Google DNS
   # Linux/macOS: Edit /etc/resolv.conf
   nameserver 8.8.8.8
   nameserver 8.8.4.4
   ```

### "JSONDecodeError"

**Cause**: Corrupted session files

**Solution**:
```bash
rm -rf ~/.spotify_tidal_config/
```

## Platform-Specific Issues

### Linux

#### Problem: "Permission denied" when creating config directory

**Solution**:
```bash
chmod 755 ~
mkdir -p ~/.spotify_tidal_config
chmod 700 ~/.spotify_tidal_config
```

### macOS

#### Problem: "SSL: CERTIFICATE_VERIFY_FAILED"

**Solution**:
```bash
# Install certificates
/Applications/Python\ 3.x/Install\ Certificates.command

# Or
pip install --upgrade certifi
```

### Windows

#### Problem: Browser not opening

**Solution**:
```powershell
# Ensure default browser is set
# Control Panel > Default Programs > Set Default Programs
```

#### Problem: Environment variables not persisting

**Solution**:
```powershell
# Use System Properties > Environment Variables
# Or use PowerShell profile
notepad $PROFILE
# Add export commands there
```

## CJK-Specific Issues

### Very Low CJK Track Match Rate (< 30%)

**Expected**: CJK tracks typically have 40-60% match rate due to:
- Romanization differences
- Character song metadata variations
- Limited availability outside Japan

**Improvements**:

1. **Lower CJK Threshold**
   ```python
   self.cjk_match_threshold = 60  # Was 70
   ```

2. **Manual Search**
   - Use missing tracks file
   - Search with romanized artist names
   - Look for compilations/OST albums

3. **Alternative Services**
   - Some CJK content may be exclusive to region-specific services
   - Consider services like Apple Music Japan, LINE Music, etc.

## Getting Help

If your issue isn't covered here:

1. **Check Logs**
   - Review console output
   - Look for specific error messages

2. **Enable Debug Logging**
   ```python
   # In script.py line 25
   logging.basicConfig(level=logging.DEBUG, ...)
   ```

3. **Create Issue on GitHub**
   - Include error messages
   - Include Python version
   - Include OS information
   - Include relevant log output (redact credentials!)

4. **Community Support**
   - Check GitHub Issues
   - Search for similar problems
   - Ask in Discussions section

## Prevention Tips

1. **Use Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Keep Dependencies Updated**
   ```bash
   pip install --upgrade -r requirements.txt
   ```

3. **Regular Session Cleanup**
   ```bash
   # Monthly cleanup
   rm -rf ~/.spotify_tidal_config/
   ```

4. **Test with Small Playlists First**
   - Verify everything works before transferring large playlists

5. **Backup Playlists**
   - Keep Spotify playlists intact
   - Transfer creates new Tidal playlist (doesn't delete source)

## Next Steps

- See [CONFIGURATION.md](CONFIGURATION.md) for customization
- See [SECURITY.md](SECURITY.md) for security best practices
- See [USAGE.md](USAGE.md) for detailed usage instructions
