# Additional Issues Found - Code Review

## Critical Issues

### 1. **Potential AttributeError: Tidal Track Artist**
**Location**: script.py:706, 713, 677

**Issue**:
```python
artist_score = fuzz.ratio(original_track.artist.lower(), tidal_track.artist.name.lower())
# If tidal_track.artist is None, this will crash with AttributeError
```

**Impact**: Application crash during track matching

**Fix**: Add None checks before accessing artist.name:
```python
if not tidal_track.artist or not hasattr(tidal_track.artist, 'name'):
    artist_score = 0
else:
    artist_score = fuzz.ratio(original_track.artist.lower(), tidal_track.artist.name.lower())
```

### 2. **Potential KeyError/TypeError: Spotify API Response**
**Location**: script.py:605-614

**Issue**:
```python
track = item['track']
artists = ', '.join([artist['name'] for artist in track['artists']])
title=track['name'],
album=track['album']['name'],
```

**Problems**:
- `track['artists']` could be empty list
- `artist['name']` could be missing
- `track['album']` could be None
- `track['name']` could be None

**Impact**: Application crash when processing certain tracks

**Fix**: Add defensive checks:
```python
if not track.get('artists'):
    artists = 'Unknown Artist'
else:
    artists = ', '.join([a.get('name', 'Unknown') for a in track['artists']])

title = track.get('name', 'Unknown Track')
album = track.get('album', {}).get('name', 'Unknown Album') if track.get('album') else 'Unknown Album'
duration_ms = track.get('duration_ms', 0)
```

### 3. **Empty Playlist Not Handled**
**Location**: script.py:830-836

**Issue**:
```python
tracks = self.get_spotify_playlist_tracks(spotify_playlist_id)
print(f"Retrieved {len(tracks)} tracks from Spotify")

# No check if tracks is empty - continues to create playlist anyway
```

**Impact**: Creates empty Tidal playlist, wastes API calls

**Fix**:
```python
tracks = self.get_spotify_playlist_tracks(spotify_playlist_id)
print(f"Retrieved {len(tracks)} tracks from Spotify")

if not tracks:
    print("⚠️  Playlist is empty - nothing to transfer")
    return {
        'success': False,
        'error': 'Source playlist contains no tracks'
    }
```

## Medium Priority Issues

### 4. **Inefficient Session Validation**
**Location**: script.py:448-460

**Issue**:
```python
def _validate_session(self) -> bool:
    search_result = self.session.search("test", [tidalapi.Track], limit=1)
    return search_result is not None
```

**Problems**:
- Makes actual API call just to validate
- Wastes API quota
- Adds unnecessary latency
- Called multiple times during authentication

**Impact**: Unnecessary API calls, slower authentication

**Better approach**:
```python
def _validate_session(self) -> bool:
    # Check if required session attributes exist without API call
    try:
        if not self.session:
            return False
        # Check if session has required auth attributes
        return (hasattr(self.session, 'session_id') and self.session.session_id) or \
               (hasattr(self.session, 'access_token') and self.session.access_token)
    except Exception as e:
        logger.debug(f"Session validation failed: {e}")
        return False
```

### 5. **No Input Validation on Configuration**
**Location**: script.py:495-498

**Issue**:
```python
self.match_threshold = 80          # No validation
self.cjk_match_threshold = 70      # Could be negative or > 100
self.max_search_results = 15       # Could be 0 or negative
```

**Impact**: Invalid values could cause crashes or unexpected behavior

**Fix**: Add validation in `__init__`:
```python
def __init__(self, spotify_client_id: str, spotify_client_secret: str,
             spotify_redirect_uri: str = "http://127.0.0.1:8080"):
    # ... existing code ...

    # Validate and set thresholds
    self.match_threshold = max(0, min(100, 80))
    self.cjk_match_threshold = max(0, min(100, 70))
    self.max_search_results = max(1, min(50, 15))
```

### 6. **Unsafe Filename Generation**
**Location**: script.py:1003

**Issue**:
```python
safe_name = "".join(c for c in results['playlist_name'] if c.isalnum() or c in (' ', '-', '_')).rstrip()
```

**Problems**:
- Doesn't handle all edge cases (e.g., all special chars → empty string)
- Could create duplicate filenames
- Doesn't limit length (filesystem limits)

**Impact**: File creation failure, filename collisions

**Fix**:
```python
# Sanitize and ensure non-empty
safe_name = "".join(c for c in results['playlist_name'] if c.isalnum() or c in (' ', '-', '_')).rstrip()
if not safe_name:
    safe_name = "playlist"
# Limit length (255 is common filesystem limit, leave room for rest of filename)
safe_name = safe_name[:100]
```

## Low Priority Issues

### 7. **No Pagination Limit for Large Playlists**
**Location**: script.py:598-622

**Issue**: Loads entire playlist into memory at once

**Impact**: Memory issues for very large playlists (1000+ tracks)

**Recommendation**: Add optional limit or implement streaming

### 8. **Repeated CJK Character Checks**
**Location**: Multiple locations (lines 653, 669, 676, 684, etc.)

**Issue**:
```python
if TextProcessor.has_cjk_characters(track.title) or TextProcessor.has_cjk_characters(track.artist):
```
Called multiple times for same track

**Impact**: Minor performance overhead

**Optimization**: Calculate once and cache:
```python
track.is_cjk = TextProcessor.has_cjk_characters(track.title) or \
               TextProcessor.has_cjk_characters(track.artist)
```

### 9. **Missing Return Type Hints**
**Location**: Multiple functions

**Issue**: Some functions missing return type hints

**Example**:
```python
def authenticate_spotify(self) -> bool:  # ✓ Good
def get_spotify_playlists(self) -> List[Dict]:  # ✓ Good
def _validate_session(self) -> bool:  # ✓ Good
def transfer_playlist(self, ...) -> Dict:  # ✓ Good
def print_transfer_summary(self, results: Dict):  # ✗ Missing -> None
```

**Impact**: Reduced code clarity, harder to maintain

### 10. **No Rate Limit Backoff Cap**
**Location**: script.py:688-691

**Issue**:
```python
if "429" in str(e) or "rate limit" in str(e).lower():
    self.rate_limiter.backoff()
    time.sleep(self.rate_limiter.current_delay)
    continue
```

**Problem**: Infinite retry loop if rate limit persists

**Fix**: Add max retry count:
```python
rate_limit_retries = 0
max_rate_limit_retries = 3

if "429" in str(e) or "rate limit" in str(e).lower():
    if rate_limit_retries >= max_rate_limit_retries:
        logger.error("Max rate limit retries exceeded")
        break
    rate_limit_retries += 1
    self.rate_limiter.backoff()
    time.sleep(self.rate_limiter.current_delay)
    continue
```

## Summary

**Must Fix (Critical)**:
1. AttributeError on tidal_track.artist.name
2. KeyError/TypeError on Spotify API response
3. Empty playlist handling

**Should Fix (Medium)**:
4. Inefficient session validation
5. No configuration validation
6. Unsafe filename generation

**Nice to Fix (Low)**:
7. Large playlist memory usage
8. Repeated CJK checks
9. Missing return type hints
10. Rate limit retry cap

## Recommendations

1. **Immediate action**: Fix critical issues #1, #2, #3
2. **Next release**: Address medium priority issues #4, #5, #6
3. **Future enhancement**: Consider low priority optimizations
4. **Add unit tests**: Especially for error cases and edge conditions
5. **Add integration tests**: Test with mock API responses

## Testing Suggestions

Create test cases for:
- Empty playlists
- Tracks with missing metadata
- Tracks with None artist
- Playlists with special characters in names
- Rate limit scenarios
- Session validation without API calls
- Invalid configuration values
