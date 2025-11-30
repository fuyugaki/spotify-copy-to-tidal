# Usage Guide

## Quick Start

```bash
# List playlists (includes Liked Songs)
python3 script.py list

# Interactive transfer
python3 script.py transfer

# Non-interactive transfer
python3 script.py transfer --playlist-id PLAYLIST_ID --yes

# Transfer Liked Songs
python3 script.py transfer --playlist-id liked --yes

# With custom name
python3 script.py transfer --playlist-id PLAYLIST_ID --name "My Playlist" --yes

# Debug mode
python3 script.py -v transfer

# Export playlist to TXT
python3 script.py export --playlist-id PLAYLIST_ID

# Export Liked Songs
python3 script.py export --playlist-id liked

# Export to M3U format
python3 script.py export --playlist-id PLAYLIST_ID --format m3u

# Export Tidal playlist
python3 script.py export --playlist-id PLAYLIST_ID --source tidal

# Export with custom filename
python3 script.py export --playlist-id PLAYLIST_ID -o my_playlist.txt
```

## Liked Songs

Your Spotify "Liked Songs" collection appears as the first item when listing playlists. Use the special ID `liked` to transfer or export it:

```bash
python3 script.py transfer --playlist-id liked --yes
python3 script.py export --playlist-id liked
```

## Authentication

On first run, you'll authenticate with both services:

1. **Spotify**: Browser opens → Log in → Authorize → Return to terminal
2. **Tidal**: Browser opens → Log in → Authorize → Return to terminal

Sessions are saved for 24 hours in `~/.spotify_tidal_config/`.

To force re-authentication:
```bash
rm -rf ~/.spotify_tidal_config/
```

## Transfer Output

```
[1/186] Artist Name - Song Title
    ✓ Found (Score: 92%)
[2/186] Japanese Artist - 日本語タイトル (Japanese/CJK)
    Trying 4 search strategies...
    ✗ Not found
```

### Match Scores

| Score | Meaning |
|-------|---------|
| 90-100% | Excellent match |
| 80-89% | Good match |
| 70-79% | Acceptable (CJK tracks) |
| <70% | Not used (marked as not found) |

## Missing Tracks

Unmatched tracks are exported to `missing_tracks_<playlist>_<timestamp>.txt` with:
- Separated CJK and Latin track lists
- Search suggestions for manual lookup
- Romanized versions for CJK tracks

## Performance

| Playlist Size | Time |
|---------------|------|
| 50 tracks | 1-2 min |
| 100 tracks | 3-5 min |
| 200 tracks | 8-12 min |
| 500 tracks | 20-30 min |

Expected success rates:
- Western/English: 85-95%
- Japanese/CJK: 40-60%

## Playlist Export

Export playlists to TXT or M3U format for backup or use with other tools.

### Export Formats

**TXT** (default): Human-readable with track details
```
Playlist: My Playlist
Source: Spotify
Total tracks: 50
==================================================

  1. Artist - Title
     Album: Album Name
     Duration: 3:45
```

**M3U**: Standard playlist format compatible with media players
```
#EXTM3U
#PLAYLIST:My Playlist
#EXTINF:225,Artist - Title
# Album: Album Name
```

### Export Options

| Option | Description |
|--------|-------------|
| `--playlist-id` | Required. Playlist ID to export |
| `--source` | `spotify` (default) or `tidal` |
| `--format`, `-f` | `txt` (default) or `m3u` |
| `--output`, `-o` | Custom output filename |

Use `python3 script.py list` to find playlist IDs.
