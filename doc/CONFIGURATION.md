# Configuration Guide

## Environment Variables

### Required Variables

#### SPOTIFY_CLIENT_ID
Your Spotify application's Client ID.

```bash
export SPOTIFY_CLIENT_ID='abc123...'
```

#### SPOTIFY_CLIENT_SECRET
Your Spotify application's Client Secret.

```bash
export SPOTIFY_CLIENT_SECRET='def456...'
```

### Optional Variables

#### SPOTIFY_REDIRECT_URI
Custom redirect URI (default: `http://127.0.0.1:8080`).

```bash
export SPOTIFY_REDIRECT_URI='http://localhost:8888'
```

**Note**: Must match the redirect URI in your Spotify app settings.

## Configuration File (Future Enhancement)

Currently, configuration is done via environment variables and code modification. A configuration file system may be added in future versions.

## Matching Configuration

These settings control how tracks are matched between Spotify and Tidal.

### Match Thresholds

Edit in `script.py` (around line 496):

```python
self.match_threshold = 80          # Standard matching threshold
self.cjk_match_threshold = 70      # CJK-specific threshold
```

#### match_threshold (default: 80)

Controls matching strictness for Latin/English tracks.

- **Value range**: 0-100
- **Recommended range**: 75-90
- **Higher values**: More strict, fewer false matches, more not found
- **Lower values**: More lenient, more matches, possible incorrect matches

**Examples**:
- `90`: Very strict, only near-perfect matches
- `80`: Balanced (default)
- `70`: Lenient, accepts partial matches

#### cjk_match_threshold (default: 70)

Controls matching for Japanese/Chinese/Korean tracks.

- **Value range**: 0-100
- **Recommended range**: 65-80
- **Why lower**: CJK tracks often have romanization/translation differences

### Search Configuration

```python
self.max_search_results = 15       # Results to check per search
```

#### max_search_results (default: 15)

How many search results to analyze per query.

- **Value range**: 5-50
- **Recommended range**: 10-20
- **Higher values**: Better matching, slower, more API calls
- **Lower values**: Faster, fewer API calls, may miss matches

## Rate Limiting Configuration

Controls API request pacing to avoid rate limits.

Edit in `script.py` (around line 142):

```python
self.rate_limiter = RateLimiter(base_delay=0.2, max_delay=60.0)
```

### Parameters

#### base_delay (default: 0.2)

Minimum delay between API requests in seconds.

- **Value range**: 0.1-2.0
- **Recommended**: 0.2-0.5
- **Lower values**: Faster but risk rate limiting
- **Higher values**: Safer but slower

#### max_delay (default: 60.0)

Maximum delay during exponential backoff.

- **Value range**: 10-300
- **Recommended**: 30-120

## Batch Processing Configuration

Edit in `script.py` (around line 777):

```python
batch_size = 20  # Tracks added per batch
```

### batch_size (default: 20)

Number of tracks added to playlist in each batch.

- **Value range**: 10-100
- **Recommended range**: 20-50
- **Higher values**: Faster but more fragile
- **Lower values**: More reliable but slower

## Search Strategy Configuration

Maximum number of search attempts per track.

Edit in `script.py` (around line 640):

```python
max_search_attempts = min(len(search_queries), 4)
```

### max_search_attempts (default: 4)

How many different search queries to try per track.

- **Value range**: 1-8
- **Recommended range**: 3-5
- **Trade-off**: More attempts = better matching but slower and more API calls

## Session Configuration

Controls session persistence behavior.

### Session Expiration

Edit in `script.py` (around line 247 and 285):

```python
if time.time() - data['timestamp'] > 86400:  # 24 hours
```

Change `86400` to desired seconds:
- `43200`: 12 hours
- `86400`: 24 hours (default)
- `604800`: 7 days

**Warning**: Longer sessions may be rejected by API providers.

### Session Storage Location

Edit in `script.py` (around line 173):

```python
self.config_dir = Path.home() / ".spotify_tidal_config"
```

Change to custom location:
```python
self.config_dir = Path("/custom/path/to/config")
```

## Logging Configuration

Edit in `script.py` (around line 25):

```python
logging.basicConfig(level=logging.INFO, ...)
```

### Log Levels

```python
logging.DEBUG     # Verbose output for debugging
logging.INFO      # Standard output (default)
logging.WARNING   # Only warnings and errors
logging.ERROR     # Only errors
```

### Custom Logging

For more control:

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('transfer.log'),  # Log to file
        logging.StreamHandler()                # Log to console
    ]
)
```

## Retry Configuration

Edit retry behavior in various methods:

### Authentication Retries

```python
# Line ~262
def authenticate(self, max_retries: int = 3) -> bool:
```

Change `max_retries` to desired number of attempts.

### Playlist Creation Retries

```python
# Line ~748
max_retries = 3
```

### Batch Add Retries

```python
# Line ~783
max_retries = 3
```

## Text Processing Configuration

### CJK Character Detection

The tool automatically detects Chinese, Japanese, and Korean characters using Unicode ranges.

No configuration needed, but you can modify detection in `TextProcessor.has_cjk_characters()` (line ~56).

### Normalization Rules

Edit `TextProcessor.normalize_text()` (line ~76) to customize:

```python
# Current rules:
# - Remove parentheses content: (TV Size), (Opening), etc.
# - Remove bracket content: [Remastered], etc.
# - Remove featuring info: feat., ft., featuring
```

Add custom rules:
```python
text = re.sub(r'your_pattern', '', text)
```

## Performance Tuning

### For Speed

```python
self.match_threshold = 85              # Higher threshold
self.max_search_results = 10           # Fewer results
max_search_attempts = 3                # Fewer attempts
batch_size = 50                        # Larger batches
base_delay = 0.1                       # Faster requests
```

### For Accuracy

```python
self.match_threshold = 75              # Lower threshold
self.max_search_results = 20           # More results
max_search_attempts = 6                # More attempts
batch_size = 10                        # Smaller batches
base_delay = 0.5                       # Slower requests
```

### For Large Playlists (500+ tracks)

```python
batch_size = 50                        # Larger batches
self.max_search_results = 12           # Moderate results
max_search_attempts = 3                # Fewer attempts
base_delay = 0.3                       # Moderate pacing
```

## Configuration Best Practices

1. **Start with defaults** - They work well for most cases
2. **Change one setting at a time** - Easier to identify impacts
3. **Test with small playlists** - Before processing large ones
4. **Monitor API rate limits** - Adjust delays if you hit limits
5. **Keep match thresholds reasonable** - Too low = false matches, too high = missing tracks

## Configuration Examples

### Example 1: Fast Mode (Small Playlists)

```python
self.match_threshold = 85
self.max_search_results = 8
max_search_attempts = 2
batch_size = 50
base_delay = 0.1
```

### Example 2: Accurate Mode (Important Playlists)

```python
self.match_threshold = 75
self.cjk_match_threshold = 65
self.max_search_results = 25
max_search_attempts = 6
base_delay = 0.5
```

### Example 3: CJK-Focused Mode

```python
self.match_threshold = 80
self.cjk_match_threshold = 65
self.max_search_results = 20
max_search_attempts = 8  # More attempts for CJK
```

## Next Steps

- See [USAGE.md](USAGE.md) for how to use the tool
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues
- See [SECURITY.md](SECURITY.md) for security considerations
