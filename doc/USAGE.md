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
    ✗ Not found automatically
```

### Match Scores

| Score | Meaning |
|-------|---------|
| 90-100% | Excellent match |
| 80-89% | Good match |
| 70-79% | Acceptable (CJK tracks) |
| <70% | Not used (marked as not found) |

## Interactive Track Fallback

When a track isn't found automatically in interactive mode, you'll see options to manually find it:

```
  ⚠️  Could not automatically match: 井内 竜次 - WHEEL
      Album: NieR:Automata

      1. Show near matches (3 found)
      2. Search by artist on Tidal
      3. Custom search
      4. Lookup artist aliases (MusicBrainz)
      5. Skip this track
      6. Skip all remaining unfound tracks

      Choice (1-6):
```

### Options Explained

| Option | Description |
|--------|-------------|
| **Near matches** | Shows tracks that scored below the threshold but might be correct |
| **Search by artist** | Find the artist on Tidal and browse their top tracks |
| **Custom search** | Enter your own search query |
| **MusicBrainz lookup** | Find alternate names/romanizations for the artist (e.g., `井内竜次` → `Ryuji Iuchi`) |
| **Skip** | Skip this track and continue |
| **Skip all** | Skip all remaining unfound tracks without prompting |

### MusicBrainz Artist Lookup

MusicBrainz stores alternate names and aliases for artists worldwide. This is especially useful for non-Latin artists:

```
      Looking up artist on MusicBrainz: 井内 竜次

      --- MusicBrainz Results ---
      1. 井内竜次 (score: 100%)
         Aliases: Iuchi, Ryuji [Sort name], Ryuji Iuchi, IUCHI Ryuuji
      0. Back to options

      Select artist (0-1): 1

      --- Search with name ---
      1. 井内竜次 + WHEEL
      2. Iuchi, Ryuji + WHEEL
      3. Ryuji Iuchi + WHEEL
      0. Back

      Select name to search (0-3):
```

### Disabling Interactive Fallback

Use `--yes` flag for fully automated transfers (no prompts):

```bash
python3 script.py transfer --playlist-id PLAYLIST_ID --yes
```

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

### Interactive Menu

After selecting a playlist, choose an action:
```
What would you like to do?
  1. Transfer to Tidal
  2. Export to TXT file
  3. Export to TXT file (with Spotify links)
  4. Export to M3U file
  b. Back to playlist list
  q. Quit
```

After completing an action, you'll return to the playlist list to continue working.

### Export Formats

**txt** (default): Human-readable with track details
```
  1. Artist - Title
     Album: Album Name
     Duration: 3:45
```

**txt-links**: With Spotify/Tidal URLs
```
  1. Artist - Title
     Album: Album Name
     Spotify: https://open.spotify.com/track/xxxxx
```

**m3u**: Standard M3U playlist format
```
#EXTM3U
#PLAYLIST:My Playlist
#EXTINF:225,Artist - Title

```

### Export Options

| Option | Description |
|--------|-------------|
| `--playlist-id` | Required. Playlist ID to export (or `liked`) |
| `--source` | `spotify` (default) or `tidal` |
| `--format`, `-f` | `txt`, `txt-links`, or `m3u` (default: txt) |
| `--output`, `-o` | Custom output filename |

Use `python3 script.py list` to find playlist IDs.
