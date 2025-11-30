# Spotify to Tidal Playlist Transfer Tool

Transfer your playlists from Spotify to Tidal with intelligent track matching, including enhanced support for Japanese/CJK music content.

## Features

- **Smart Track Matching**: Multiple fuzzy matching strategies for accurate track identification
- **CJK Character Support**: Enhanced matching for Japanese, Korean, and Chinese music
- **Session Persistence**: Saves authentication for 24 hours (no repeated logins)
- **Rate Limiting**: Intelligent API throttling with exponential backoff
- **Detailed Reporting**: Comprehensive statistics with language-specific success rates
- **Missing Track Export**: Exports unmatched tracks with manual search suggestions
- **Batch Processing**: Efficiently handles large playlists with progress tracking
- **Error Recovery**: Robust retry logic for network issues

## Quick Start

### 1. Install

```bash
# Clone the repository
git clone https://github.com/yourusername/spotify-copy-to-tidal.git
cd spotify-copy-to-tidal

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

Set up your Spotify API credentials:

1. Create a Spotify app at [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Add `http://127.0.0.1:8080` as a redirect URI
3. Set environment variables:

```bash
export SPOTIFY_CLIENT_ID='your_client_id_here'
export SPOTIFY_CLIENT_SECRET='your_client_secret_here'
```

### 3. Run

```bash
python3 script.py
```

Follow the interactive prompts to authenticate and transfer playlists.

## Requirements

- Python 3.8 or higher
- Spotify Premium account
- Tidal subscription
- Spotify Developer App credentials

## Example Output

```
Transfer completed!
Playlist: My Music Collection (from Spotify)
Total tracks: 186
Successfully transferred: 139
Not found: 47
Success rate: 74.7%

Success by language:
Japanese/CJK tracks: 37/79 (46.8%)
Latin/English tracks: 102/107 (95.3%)

Missing tracks exported to: missing_tracks_My_Music_Collection_20250816_143022.txt
```

## Documentation

Comprehensive documentation is available in the [`/doc`](doc/) directory:

- **[Installation Guide](doc/INSTALLATION.md)** - Complete setup instructions
- **[Usage Guide](doc/USAGE.md)** - How to use the tool
- **[Configuration Guide](doc/CONFIGURATION.md)** - Customization options
- **[Troubleshooting Guide](doc/TROUBLESHOOTING.md)** - Solutions to common issues
- **[Security Guide](doc/SECURITY.md)** - Security best practices

## How It Works

### Smart Matching

The tool uses multiple strategies to find tracks:

1. **Exact Matching**: Direct title and artist comparison
2. **Normalized Matching**: Removes parentheses, brackets, and special formatting
3. **Fuzzy Matching**: Handles slight differences in spelling
4. **Token Sorting**: Matches despite word order differences
5. **Partial Matching**: When one string contains the other
6. **Latin Extraction**: For CJK tracks, extracts romanized portions

### Language Support

Different matching thresholds for different character sets:

- **Latin/English tracks**: 80% similarity threshold
- **CJK tracks**: 70% similarity threshold (accounts for romanization differences)

### Rate Limiting

Built-in rate limiting prevents API throttling:

- Base delay: 0.2 seconds between requests
- Exponential backoff on rate limit errors
- Configurable delays and retry logic

## Performance

Typical transfer times:

- **50 tracks**: 1-2 minutes
- **100 tracks**: 3-5 minutes
- **200 tracks**: 8-12 minutes
- **500 tracks**: 20-30 minutes

Success rates vary by content:

- **Western/English music**: 85-95%
- **Japanese/CJK music**: 40-60%
- **Obscure/indie content**: 50-70%

## Configuration

Customize matching behavior by editing `script.py`:

```python
# Match thresholds (0-100)
self.match_threshold = 80          # Standard tracks
self.cjk_match_threshold = 70      # CJK tracks

# Search settings
self.max_search_results = 15       # Results per search
max_search_attempts = 4            # Queries per track
```

See [Configuration Guide](doc/CONFIGURATION.md) for details.

## Troubleshooting

### Common Issues

**Authentication fails**
- Verify credentials are set correctly
- Ensure redirect URI is exactly `http://127.0.0.1:8080`
- Clear session files: `rm -rf ~/.spotify_tidal_config/`

**Low match rate**
- Check if content is available on Tidal
- Review missing tracks file for manual search
- Adjust match thresholds (see Configuration Guide)

**Rate limiting errors**
- Increase base delay in configuration
- Reduce search attempts per track
- Wait 5-10 minutes and retry

See [Troubleshooting Guide](doc/TROUBLESHOOTING.md) for more solutions.

## Security

### Best Practices

- **Use environment variables** for credentials (never hardcode)
- **Session files** are stored locally with restricted permissions
- **No data leaves your computer** except API calls
- **Minimal API scopes** requested (read-only for Spotify)

**Important**: Current session storage uses basic obfuscation, not encryption. For production use, implement proper encryption or use system keychain.

See [Security Guide](doc/SECURITY.md) for detailed information.

## Known Limitations

- **Tidal API variations**: Authentication methods may vary by region
- **Licensing restrictions**: Some tracks unavailable in your region
- **CJK romanization**: Multiple romanization systems affect matching
- **Rate limiting**: Large playlists take time to process
- **Memory usage**: All tracks loaded into memory (may be an issue for 1000+ track playlists)

## Contributing

Contributions welcome! Areas for improvement:

- [ ] Enhanced CJK matching algorithms
- [ ] Additional streaming service support
- [ ] Proper encryption for session storage
- [ ] Batch playlist processing
- [ ] GUI interface
- [ ] Configuration file support
- [ ] Unit tests and integration tests

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for **personal use only**. Please respect the terms of service of both Spotify and Tidal:

- [Spotify Developer Terms](https://developer.spotify.com/terms)
- [Tidal Terms of Service](https://tidal.com/terms)

The authors are not responsible for:
- Terms of service violations
- Data loss during transfer
- API rate limit violations
- Account suspensions

## Acknowledgments

Built with:

- [Spotipy](https://github.com/plamere/spotipy) - Spotify Web API wrapper
- [python-tidal](https://github.com/tamland/python-tidal) - Tidal API wrapper
- [FuzzyWuzzy](https://github.com/seatgeek/fuzzywuzzy) - Fuzzy string matching

## Support

- **Documentation**: See [`/doc`](doc/) directory
- **Issues**: [GitHub Issues](https://github.com/yourusername/spotify-copy-to-tidal/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/spotify-copy-to-tidal/discussions)

## Changelog

### Version 2.0 (Current)

**Fixed**:
- ✅ Security: Environment variable support (no hardcoded credentials)
- ✅ Security: Proper file permissions on session storage
- ✅ Security: Specific exception handling (no bare `except` clauses)
- ✅ Bug: Correct token saving (full token_info dict)
- ✅ Bug: Removed unused imports
- ✅ Bug: Fixed duplicate datetime import
- ✅ Performance: Reduced API calls (4 attempts max, down from 8)
- ✅ Error handling: Atomic file writes for session storage
- ✅ Error handling: Better exception specificity

**Added**:
- ✅ Comprehensive documentation (5 guides in `/doc`)
- ✅ Security warnings in code comments
- ✅ Better error messages

### Version 1.0

- Initial release
- Basic playlist transfer functionality
- CJK character support
- Session persistence
- Missing tracks export

---

Made with ❤️ for music lovers who use multiple streaming platforms
