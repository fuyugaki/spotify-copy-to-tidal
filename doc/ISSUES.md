# Issues & Roadmap

**Status**: Production-ready with caveats | **Last Updated**: 2025-11-30

## Summary

| Category | Status |
|----------|--------|
| Critical/Security | ✅ All fixed |
| High Priority | ⚠️ 3 remaining (quick fixes) |
| Tests | ❌ None |

## ✅ Completed (v0.0.4)

**Interactive Fallback**: Manual search options when tracks aren't found automatically
- Near matches display (tracks below threshold)
- Artist search on Tidal (browse top tracks)
- Custom search query
- MusicBrainz artist alias lookup (romanized names for international artists)
- Skip track / Skip all remaining options

**MusicBrainz Integration**: External database lookup for artist aliases and alternate names

## ✅ Completed (v0.0.3)

**Features**: Liked Songs support, playlist export (txt/txt-links/m3u), interactive menu loop, full CLI with subcommands

## ✅ Completed (v0.0.2)

**Security**: Environment variables, specific exception handling, file permissions (0700/0600)

**Bugs Fixed**: AttributeError on tidal_track.artist, KeyError on Spotify responses, empty playlist handling, token saving, filename sanitization

**Performance**: API calls reduced 8→4 per track, session validation without API calls

## ⚠️ High Priority

### 1. Input Validation (5 min)
```python
# script.py:495-498 - Add bounds checking
self.match_threshold = max(0, min(100, 80))
self.cjk_match_threshold = max(0, min(100, 70))
self.max_search_results = max(1, min(50, 15))
```

### 2. Rate Limit Retry Cap (10 min)
```python
# script.py:645-651 - Add max retry counter to prevent infinite loops
rate_limit_retries = 0
max_rate_limit_retries = 3
```

### 3. Division Safety (10 min)
Review all division operations for potential divide-by-zero.

## 🟡 Medium Priority

| Issue | Effort | Notes |
|-------|--------|-------|
| Large playlist support | 1h | Add optional track limit, batch processing |
| CJK detection caching | 30m | Cache `is_cjk` in Track dataclass |
| Missing return type hints | 5m | `print_transfer_summary`, `_export_missing_tracks`, `main` |
| Config file support | 2h | YAML/JSON configuration |

## 🟢 Low Priority

| Issue | Effort | Notes |
|-------|--------|-------|
| Unit tests | 4-8h | TextProcessor, SessionManager, matching logic |
| Async processing | 8-12h | Concurrent track searching, 50-70% speedup |
| Log level via env var | 5m | `LOG_LEVEL` environment variable |

## Known Limitations (Won't Fix)

- CJK match rates (40-60%) - inherent romanization challenges
- Tidal regional locks - API limitation
- Some content not on Tidal - licensing limitation
