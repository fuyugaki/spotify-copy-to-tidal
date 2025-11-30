# Configuration Guide

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SPOTIFY_CLIENT_ID` | Yes | - | Spotify app Client ID |
| `SPOTIFY_CLIENT_SECRET` | Yes | - | Spotify app Client Secret |
| `SPOTIFY_REDIRECT_URI` | No | `http://127.0.0.1:8080` | OAuth redirect URI |

## Code Configuration

All settings are in `script.py`. A config file system may be added in future versions.

### Match Thresholds (~line 500)

```python
self.match_threshold = 80       # Latin tracks (0-100)
self.cjk_match_threshold = 70   # CJK tracks (0-100)
self.max_search_results = 15    # Results per search (5-50)
```

- **Higher threshold** = stricter matching, fewer false positives, more "not found"
- **Lower threshold** = lenient matching, more matches, possible incorrect matches

### Rate Limiting (~line 137)

```python
RateLimiter(base_delay=0.2, max_delay=60.0)
```

- `base_delay`: Seconds between API requests (0.1-2.0)
- `max_delay`: Maximum backoff delay (10-300)

### Search Strategy (~line 658)

```python
max_search_attempts = min(len(search_queries), 4)
```

Attempts per track (1-8). More = better matching but slower.

### Batch Size (~line 810)

```python
batch_size = 20  # Tracks per batch (10-100)
```

### Session Expiration (~line 247)

```python
if time.time() - data['timestamp'] > 86400:  # 24 hours
```

Change `86400` to desired seconds (43200=12h, 604800=7d).

## Tuning Profiles

### Fast Mode (small playlists)
```python
self.match_threshold = 85
self.max_search_results = 8
max_search_attempts = 2
base_delay = 0.1
```

### Accurate Mode (important playlists)
```python
self.match_threshold = 75
self.cjk_match_threshold = 65
self.max_search_results = 25
max_search_attempts = 6
```

### CJK-Focused Mode
```python
self.cjk_match_threshold = 65
self.max_search_results = 20
max_search_attempts = 8
```
