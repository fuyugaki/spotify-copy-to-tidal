# Usage Guide

## Quick Start

1. Ensure environment variables are set (see [INSTALLATION.md](INSTALLATION.md))
2. Run the script:
   ```bash
   python3 script.py
   ```
3. Follow the interactive prompts

## Detailed Usage

### Step 1: Authentication

When you run the script, it will authenticate with both services:

#### Spotify Authentication

- A browser window will open automatically
- Log in to your Spotify account
- Authorize the application
- The browser will redirect to a confirmation page
- Return to the terminal

Your Spotify session is saved for 24 hours, so you won't need to re-authenticate on subsequent runs.

#### Tidal Authentication

- A browser window will open automatically
- Log in to your Tidal account
- Authorize the application
- Return to the terminal

Your Tidal session is also saved for 24 hours.

### Step 2: Select a Playlist

The tool will display all your Spotify playlists:

```
=== Your Spotify Playlists ===
 1. My Awesome Playlist (186 tracks) - YourUsername
 2. Workout Mix (45 tracks) - YourUsername
 3. Road Trip (78 tracks) - FriendUsername
...

Choose a playlist to transfer (1-3, or 'q' to quit):
```

- Enter the number of the playlist you want to transfer
- Enter `q` to quit the application

### Step 3: Confirm Transfer

```
You selected: My Awesome Playlist
This playlist has 186 tracks
Proceed with transfer? (y/N):
```

- Enter `y` to proceed
- Enter `n` or press Enter to cancel

### Step 4: Transfer Progress

The tool will show real-time progress:

```
--- Searching for tracks on Tidal ---
[1/186] Artist Name - Song Title
    Trying 4 search strategies...
    Match found: 'Artist Name - Song Title' (Score: 92.5%)
  ✓ Found (Score: 92%)
[2/186] Another Artist - Another Song (Japanese/CJK)
    Trying 4 search strategies...
  ✗ Not found
...
  Progress: 75.5% success rate so far
    CJK tracks: 46.8% success, Latin tracks: 88.2% success
```

### Step 5: Results

After completion, you'll see a detailed summary:

```
🎉 Transfer completed!
Playlist: My Awesome Playlist (from Spotify)
Total tracks: 186
Successfully transferred: 139
Not found: 47
Success rate: 74.7%

📊 Success by language:
Japanese/CJK tracks: 37/79 (46.8%)
Latin/English tracks: 102/107 (95.3%)

📝 Tracks not found on Tidal:
  Latin/English tracks:
    • Artist - Song Title
    • Another Artist - Another Song
    ... and 3 more
  Japanese/CJK tracks:
    • アーティスト - 曲名
    • 声優名 - キャラソン
    ... and 40 more

📁 Missing tracks exported to: missing_tracks_My_Awesome_Playlist_20250816_143022.txt
```

## Understanding the Output

### Track Matching Indicators

- **✓ Found (Score: 95%)** - Track successfully matched with high confidence
- **✓ Found (Score: 72%)** - Track matched with lower confidence (may need manual verification)
- **✗ Not found** - No suitable match found on Tidal

### Match Scores

- **90-100%**: Excellent match, almost certainly correct
- **80-89%**: Good match, likely correct
- **70-79%**: Acceptable match (for CJK tracks), may need verification
- **Below 70%**: Not used (track marked as not found)

### Language Detection

The tool automatically detects Japanese/CJK characters and:
- Uses different matching strategies (romanization, Latin extraction)
- Applies lower matching thresholds (70% vs 80%)
- Provides language-specific search suggestions

## Missing Tracks File

When tracks aren't found, the tool exports a detailed file with search suggestions:

```
missing_tracks_[PlaylistName]_[Timestamp].txt
```

### File Contents

The file includes:
- Summary statistics
- Separated lists for Latin and CJK tracks
- Search suggestions for each track:
  - Normalized titles (without parentheses, brackets)
  - Romanized versions for CJK tracks
  - Alternative search queries
  - Voice actor name extraction (for character songs)

### Manual Search Tips

Use the suggestions in the missing tracks file to search Tidal manually:

1. Copy suggested search query
2. Search in Tidal app or web player
3. Add tracks manually to your transferred playlist

## Advanced Usage

### Customizing Match Thresholds

Edit `script.py` to adjust matching behavior:

```python
# Around line 496
self.match_threshold = 80          # Standard threshold (0-100)
self.cjk_match_threshold = 70      # CJK threshold (lower is more lenient)
self.max_search_results = 15       # Results per search
```

**Higher threshold** = Stricter matching (fewer false positives, more not found)
**Lower threshold** = Lenient matching (more matches, possible false positives)

### Batch Processing

To transfer multiple playlists, run the script multiple times or modify it to loop through playlists.

## Session Management

### Session Files Location

Sessions are stored in:
```
~/.spotify_tidal_config/
├── spotify_session.json
└── tidal_session.json
```

### Session Expiration

Both sessions expire after 24 hours. After expiration, you'll need to re-authenticate.

### Clearing Sessions

To force re-authentication:

```bash
rm -rf ~/.spotify_tidal_config/
```

## Performance Considerations

### Large Playlists

For playlists with hundreds of tracks:
- Expect longer processing times (2-4 tracks per second)
- The tool includes rate limiting to avoid API throttling
- Progress updates every 10 tracks
- Can take 5-15 minutes for 200+ track playlists

### Network Issues

If you experience network problems:
- The tool has built-in retry logic
- Temporary failures are automatically retried
- Rate limit errors trigger exponential backoff

## Common Workflows

### Workflow 1: Single Playlist Transfer

```bash
python3 script.py
# Authenticate once
# Select playlist
# Review results
```

### Workflow 2: Multiple Playlists

```bash
# First playlist
python3 script.py
# [select playlist 1]

# Second playlist (uses cached authentication)
python3 script.py
# [select playlist 2]
```

### Workflow 3: Periodic Sync

Set up a weekly cron job:

```bash
0 0 * * 0 cd /path/to/script && python3 script.py < input.txt
```

Where `input.txt` contains:
```
1
y
```

## Next Steps

- See [CONFIGURATION.md](CONFIGURATION.md) for customization
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues
- See [SECURITY.md](SECURITY.md) for security considerations
