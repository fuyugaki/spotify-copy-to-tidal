#!/usr/bin/env python3
"""
Spotify to Tidal Playlist Transfer Tool (Enhanced)
Copies playlists from Spotify to Tidal with robust authentication and error handling
"""

import os
import json
import time
import logging
import hashlib
import re
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from fuzzywuzzy import fuzz
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import tidalapi
import requests


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class Track:
    """Represents a track with metadata"""
    title: str
    artist: str
    album: str
    duration_ms: int = 0
    spotify_id: str = ""
    tidal_id: str = ""

    def __str__(self):
        return f"{self.artist} - {self.title}"


class AuthenticationError(Exception):
    """Custom exception for authentication failures"""
    pass


class TextProcessor:
    """Handles text processing for different languages and character sets"""
    
    @staticmethod
    def has_cjk_characters(text: str) -> bool:
        """Check if text contains Chinese, Japanese, or Korean characters"""
        for char in text:
            if '\u4e00' <= char <= '\u9fff' or \
               '\u3040' <= char <= '\u309f' or \
               '\u30a0' <= char <= '\u30ff' or \
               '\uac00' <= char <= '\ud7af':
                return True
        return False
    
    @staticmethod
    def extract_latin_parts(text: str) -> str:
        """Extract Latin characters and common punctuation from text"""
        # Keep Latin letters, numbers, spaces, and common punctuation
        latin_text = re.sub(r'[^\w\s\-\.\(\)\[\]\'\"&!]', ' ', text, flags=re.ASCII)
        # Clean up multiple spaces
        latin_text = ' '.join(latin_text.split())
        return latin_text.strip()
    
    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalize text for better matching"""
        # Convert to lowercase
        text = text.lower()
        # Remove extra whitespace
        text = ' '.join(text.split())
        # Remove common prefixes/suffixes
        text = re.sub(r'\s*\(.*?\)\s*', ' ', text)  # Remove parentheses content
        text = re.sub(r'\s*\[.*?\]\s*', ' ', text)  # Remove bracket content
        text = re.sub(r'\s*-\s*(tv\s+edit|edit|version|ver\.?)\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s*(feat\.?|ft\.?|featuring)\s+.*', '', text, flags=re.IGNORECASE)
        return text.strip()
    
    @staticmethod
    def generate_search_variants(title: str, artist: str) -> List[str]:
        """Generate multiple search variants for better matching"""
        variants = []
        
        # Original
        variants.append(f"{artist} {title}")
        variants.append(f"{title} {artist}")
        variants.append(title)
        
        # Normalized versions
        norm_title = TextProcessor.normalize_text(title)
        norm_artist = TextProcessor.normalize_text(artist)
        
        if norm_title != title or norm_artist != artist:
            variants.append(f"{norm_artist} {norm_title}")
            variants.append(f"{norm_title} {norm_artist}")
            variants.append(norm_title)
        
        # Latin-only versions if text contains CJK
        if TextProcessor.has_cjk_characters(title) or TextProcessor.has_cjk_characters(artist):
            latin_title = TextProcessor.extract_latin_parts(title)
            latin_artist = TextProcessor.extract_latin_parts(artist)
            
            if latin_title:
                variants.append(latin_title)
                if latin_artist:
                    variants.append(f"{latin_artist} {latin_title}")
                    variants.append(f"{latin_title} {latin_artist}")
            
            if latin_artist and not latin_title:
                variants.append(latin_artist)
        
        # Artist-only search as last resort
        if len(artist.split()) <= 3:  # Only for short artist names
            variants.append(artist)
        
        # Remove duplicates while preserving order
        unique_variants = []
        seen = set()
        for variant in variants:
            variant = variant.strip()
            if variant and variant not in seen and len(variant) > 2:
                unique_variants.append(variant)
                seen.add(variant)
        
        return unique_variants


class RateLimiter:
    """Rate limiter with exponential backoff"""
    
    def __init__(self, base_delay: float = 0.2, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.current_delay = base_delay
        self.last_request_time = 0
        
    def wait(self):
        """Wait according to current rate limit"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.current_delay:
            sleep_time = self.current_delay - time_since_last
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()
    
    def backoff(self):
        """Increase delay due to rate limiting"""
        self.current_delay = min(self.current_delay * 2, self.max_delay)
        logger.warning(f"Rate limited, backing off to {self.current_delay}s delay")
    
    def reset(self):
        """Reset delay back to base"""
        self.current_delay = self.base_delay


class SessionManager:
    """Manages persistent session storage

    WARNING: Session data is stored locally in JSON format with basic obfuscation.
    For production use, implement proper encryption or use a secure credential store.
    Ensure the config directory has appropriate file permissions (0700).
    """

    def __init__(self, config_dir: str = ".spotify_tidal_config"):
        self.config_dir = Path.home() / config_dir
        self.config_dir.mkdir(mode=0o700, exist_ok=True)
        self.spotify_config = self.config_dir / "spotify_session.json"
        self.tidal_config = self.config_dir / "tidal_session.json"

        # Ensure config files have restricted permissions
        self._set_secure_permissions()

    def _set_secure_permissions(self):
        """Set secure file permissions on config files"""
        for config_file in [self.spotify_config, self.tidal_config]:
            if config_file.exists():
                os.chmod(config_file, 0o600)

    def _simple_encrypt(self, data: str, key: str) -> str:
        """Basic obfuscation for local storage (NOT cryptographically secure)

        WARNING: This is obfuscation, not encryption. Tokens can be easily extracted.
        For production, use proper encryption libraries like cryptography.fernet
        """
        key_hash = hashlib.sha256(key.encode()).digest()
        encrypted = ""
        for i, char in enumerate(data):
            encrypted += chr(ord(char) ^ key_hash[i % len(key_hash)])
        return encrypted.encode('latin1').hex()

    def _simple_decrypt(self, encrypted_hex: str, key: str) -> str:
        """Basic de-obfuscation for local storage"""
        try:
            encrypted = bytes.fromhex(encrypted_hex).decode('latin1')
            key_hash = hashlib.sha256(key.encode()).digest()
            decrypted = ""
            for i, char in enumerate(encrypted):
                decrypted += chr(ord(char) ^ key_hash[i % len(key_hash)])
            return decrypted
        except (ValueError, UnicodeDecodeError, KeyError) as e:
            logger.debug(f"Failed to decrypt session data: {e}")
            return ""
    
    def save_spotify_session(self, token_info: dict, client_id: str):
        """Save Spotify session info"""
        try:
            data = {
                'token_info': token_info,
                'timestamp': time.time()
            }
            encrypted = self._simple_encrypt(json.dumps(data), client_id)

            # Write atomically using temp file
            temp_file = self.spotify_config.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump({'data': encrypted}, f)
            os.chmod(temp_file, 0o600)
            temp_file.replace(self.spotify_config)

        except (OSError, IOError) as e:
            logger.error(f"Failed to save Spotify session: {e}")

    def load_spotify_session(self, client_id: str) -> Optional[dict]:
        """Load Spotify session info"""
        try:
            if not self.spotify_config.exists():
                return None

            with open(self.spotify_config, 'r') as f:
                config = json.load(f)

            decrypted = self._simple_decrypt(config['data'], client_id)
            if not decrypted:
                return None

            data = json.loads(decrypted)

            # Check if token is expired (24 hours)
            if time.time() - data['timestamp'] > 86400:
                logger.info("Spotify session expired, re-authentication required")
                return None

            return data['token_info']

        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.debug(f"Failed to load Spotify session: {e}")
            return None
    
    def save_tidal_session(self, session_data: dict):
        """Save Tidal session info"""
        try:
            data = {
                'session_data': session_data,
                'timestamp': time.time()
            }

            # Write atomically using temp file
            temp_file = self.tidal_config.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f)
            os.chmod(temp_file, 0o600)
            temp_file.replace(self.tidal_config)

        except (OSError, IOError) as e:
            logger.error(f"Failed to save Tidal session: {e}")

    def load_tidal_session(self) -> Optional[dict]:
        """Load Tidal session info"""
        try:
            if not self.tidal_config.exists():
                return None

            with open(self.tidal_config, 'r') as f:
                data = json.load(f)

            # Check if session is expired (24 hours)
            if time.time() - data['timestamp'] > 86400:
                logger.info("Tidal session expired, re-authentication required")
                return None

            return data['session_data']

        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.debug(f"Failed to load Tidal session: {e}")
            return None


class TidalAuthManager:
    """Robust Tidal authentication manager with version compatibility"""
    
    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager
        self.session = None
        self.rate_limiter = RateLimiter()
    
    def authenticate(self, max_retries: int = 3) -> bool:
        """Authenticate with Tidal using version-compatible methods"""
        
        # Try to load existing session
        if self._load_existing_session():
            return True
        
        # Try authentication with retries
        for attempt in range(max_retries):
            try:
                print(f"\n--- Tidal Authentication (Attempt {attempt + 1}/{max_retries}) ---")
                
                if self._attempt_authentication():
                    self._save_session()
                    return True
                    
            except Exception as e:
                logger.warning(f"Auth attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    delay = 2 ** attempt
                    print(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
        
        raise AuthenticationError("Failed to authenticate with Tidal after multiple attempts")
    
    def _load_existing_session(self) -> bool:
        """Try to load and validate existing session"""
        try:
            session_data = self.session_manager.load_tidal_session()
            if not session_data:
                return False
            
            self.session = tidalapi.Session()
            
            # Try to restore session state (method varies by version)
            if hasattr(self.session, 'load_oauth_session') and 'access_token' in session_data:
                self.session.load_oauth_session(session_data['access_token'])
            elif hasattr(self.session, 'session_id') and 'session_id' in session_data:
                self.session.session_id = session_data['session_id']
                self.session.country_code = session_data.get('country_code', 'US')
            
            # Validate session by attempting a search
            if self._validate_session():
                print("✓ Restored existing Tidal session")
                return True
            else:
                print("Existing session expired, need to re-authenticate")
                return False
                
        except Exception as e:
            logger.debug(f"Failed to load existing session: {e}")
            return False
    
    def _attempt_authentication(self) -> bool:
        """Try authentication using version-compatible methods"""
        self.session = tidalapi.Session()
        
        # Try different authentication methods based on available API
        auth_methods = [
            self._try_oauth_simple,
            self._try_oauth_device_flow,
            self._try_legacy_oauth
        ]
        
        for method in auth_methods:
            try:
                if method():
                    return True
            except Exception as e:
                logger.debug(f"Auth method failed: {e}")
                continue
        
        return False
    
    def _try_oauth_simple(self) -> bool:
        """Try login_oauth_simple method (newer versions)"""
        if not hasattr(self.session, 'login_oauth_simple'):
            return False
        
        print("Attempting OAuth simple login...")
        print("Please check your browser for Tidal login prompt...")
        
        success = self.session.login_oauth_simple()
        
        if success and self._validate_session():
            print("✓ OAuth simple login successful")
            return True
        
        return False
    
    def _try_oauth_device_flow(self) -> bool:
        """Try device flow OAuth (some versions)"""
        if not hasattr(self.session, 'login_oauth'):
            return False
        
        try:
            print("Attempting device flow OAuth...")
            result = self.session.login_oauth()
            
            # Handle different return types
            if isinstance(result, tuple) and len(result) == 2:
                login_info, future = result
                print(f"Go to: {login_info.verification_uri}")
                print(f"Enter code: {login_info.user_code}")
                print("Waiting for authentication...")
                
                # Wait for completion with timeout
                try:
                    session = future.result(timeout=300)  # 5 minute timeout
                    if session and self._validate_session():
                        print("✓ Device flow OAuth successful")
                        return True
                except Exception as e:
                    print(f"Device flow timeout or error: {e}")
                    return False
            else:
                # Direct return
                if result and self._validate_session():
                    print("✓ OAuth successful")
                    return True
        
        except Exception as e:
            logger.debug(f"Device flow failed: {e}")
        
        return False
    
    def _try_legacy_oauth(self) -> bool:
        """Try legacy authentication methods"""
        try:
            # Some versions might have different OAuth methods
            if hasattr(self.session, 'login_with_token'):
                print("Legacy token authentication not supported in automated mode")
                return False
            
            # Last resort - check if session is somehow valid
            if self._validate_session():
                print("✓ Session already authenticated")
                return True
                
        except Exception as e:
            logger.debug(f"Legacy auth failed: {e}")
        
        return False
    
    def _validate_session(self) -> bool:
        """Validate session by checking required attributes without API call"""
        try:
            if not self.session:
                return False

            # Check if session has required authentication attributes
            # This avoids unnecessary API calls during validation
            has_session_id = hasattr(self.session, 'session_id') and self.session.session_id
            has_access_token = hasattr(self.session, 'access_token') and self.session.access_token

            return has_session_id or has_access_token

        except Exception as e:
            logger.debug(f"Session validation failed: {e}")
            return False
    
    def _save_session(self):
        """Save current session state"""
        try:
            session_data = {}
            
            # Save different attributes based on what's available
            if hasattr(self.session, 'access_token') and self.session.access_token:
                session_data['access_token'] = self.session.access_token
            
            if hasattr(self.session, 'session_id') and self.session.session_id:
                session_data['session_id'] = self.session.session_id
                
            if hasattr(self.session, 'country_code') and self.session.country_code:
                session_data['country_code'] = self.session.country_code
            
            if session_data:
                self.session_manager.save_tidal_session(session_data)
                logger.info("Tidal session saved")
                
        except Exception as e:
            logger.warning(f"Failed to save session: {e}")


class SpotifyToTidalTransfer:
    def __init__(self, spotify_client_id: str, spotify_client_secret: str, 
                 spotify_redirect_uri: str = "http://127.0.0.1:8080"):
        """Initialize the transfer tool with enhanced error handling"""
        self.spotify_client_id = spotify_client_id
        self.spotify_client_secret = spotify_client_secret
        self.spotify_redirect_uri = spotify_redirect_uri
        
        self.spotify = None
        self.tidal_auth_manager = None
        
        # Configuration
        self.match_threshold = 80
        self.cjk_match_threshold = 70  # Lower threshold for CJK tracks
        self.max_search_results = 15  # Increased for better CJK matching
        
        # Managers
        self.session_manager = SessionManager()
        self.rate_limiter = RateLimiter()
        
    def authenticate_spotify(self) -> bool:
        """Enhanced Spotify authentication with session persistence"""
        try:
            # Try to load existing token
            token_info = self.session_manager.load_spotify_session(self.spotify_client_id)
            
            scope = "playlist-read-private playlist-read-collaborative user-library-read"
            
            auth_manager = SpotifyOAuth(
                client_id=self.spotify_client_id,
                client_secret=self.spotify_client_secret,
                redirect_uri=self.spotify_redirect_uri,
                scope=scope,
                open_browser=True
            )
            
            # Use existing token if available
            if token_info:
                auth_manager.token_info = token_info
            
            self.spotify = spotipy.Spotify(auth_manager=auth_manager)

            # Test the connection
            user = self.spotify.current_user()
            print(f"✓ Spotify authenticated as: {user['display_name']}")

            # Save token info for future use
            # get_cached_token() returns the current token dict after any refresh
            current_token = auth_manager.get_cached_token()
            if current_token:
                self.session_manager.save_spotify_session(
                    current_token,
                    self.spotify_client_id
                )

            return True
            
        except Exception as e:
            logger.error(f"Spotify authentication failed: {e}")
            return False
    
    def authenticate_tidal(self) -> bool:
        """Enhanced Tidal authentication"""
        try:
            self.tidal_auth_manager = TidalAuthManager(self.session_manager)
            return self.tidal_auth_manager.authenticate()
        except AuthenticationError as e:
            print(f"✗ {e}")
            print("\nTroubleshooting tips:")
            print("1. Make sure you're logged into Tidal in your browser")
            print("2. Try clearing your browser cache and cookies for Tidal")
            print("3. Check your internet connection")
            print("4. Try running the script again in a few minutes")
            return False
        except Exception as e:
            logger.error(f"Unexpected Tidal authentication error: {e}")
            return False
    
    def get_spotify_playlists(self, include_liked: bool = True) -> List[Dict]:
        """Get all user's Spotify playlists with error handling.

        Args:
            include_liked: If True, includes "Liked Songs" as first item
        """
        if not self.spotify:
            raise Exception("Spotify not authenticated")

        playlists = []
        try:
            # Add Liked Songs as a special "playlist"
            if include_liked:
                liked_count = self._get_liked_songs_count()
                if liked_count > 0:
                    user = self.spotify.current_user()
                    playlists.append({
                        'id': 'liked',
                        'name': 'Liked Songs',
                        'description': 'Your liked songs from Spotify',
                        'tracks_count': liked_count,
                        'owner': user['display_name']
                    })

            results = self.spotify.current_user_playlists(limit=50)

            while results:
                for playlist in results['items']:
                    if playlist:
                        playlists.append({
                            'id': playlist['id'],
                            'name': playlist['name'],
                            'description': playlist.get('description', ''),
                            'tracks_count': playlist['tracks']['total'],
                            'owner': playlist['owner']['display_name']
                        })

                if results['next']:
                    self.rate_limiter.wait()
                    results = self.spotify.next(results)
                else:
                    break

            return playlists

        except Exception as e:
            logger.error(f"Failed to get Spotify playlists: {e}")
            raise

    def _get_liked_songs_count(self) -> int:
        """Get the total count of liked songs."""
        try:
            results = self.spotify.current_user_saved_tracks(limit=1)
            return results.get('total', 0)
        except Exception as e:
            logger.debug(f"Failed to get liked songs count: {e}")
            return 0

    def get_spotify_liked_songs(self) -> List[Track]:
        """Get all liked songs from Spotify."""
        if not self.spotify:
            raise Exception("Spotify not authenticated")

        tracks = []
        try:
            results = self.spotify.current_user_saved_tracks(limit=50)

            while results:
                for item in results['items']:
                    if item and item.get('track') and item['track'].get('type') == 'track':
                        track = item['track']

                        if not track.get('artists'):
                            artists = 'Unknown Artist'
                        else:
                            artists = ', '.join([a.get('name', 'Unknown') for a in track['artists'] if a])

                        title = track.get('name', 'Unknown Track')
                        album = track.get('album', {}).get('name', 'Unknown Album') if track.get('album') else 'Unknown Album'
                        duration_ms = track.get('duration_ms', 0)
                        track_id = track.get('id', '')

                        if not title or title == 'Unknown Track':
                            logger.warning(f"Skipping track with missing title: {track}")
                            continue

                        tracks.append(Track(
                            title=title,
                            artist=artists,
                            album=album,
                            duration_ms=duration_ms,
                            spotify_id=track_id
                        ))

                if results['next']:
                    self.rate_limiter.wait()
                    results = self.spotify.next(results)
                else:
                    break

            return tracks

        except Exception as e:
            logger.error(f"Failed to get liked songs: {e}")
            raise
    
    def get_spotify_playlist_tracks(self, playlist_id: str) -> List[Track]:
        """Get all tracks from a Spotify playlist with rate limiting.

        Args:
            playlist_id: Playlist ID, or 'liked' for Liked Songs
        """
        if not self.spotify:
            raise Exception("Spotify not authenticated")

        # Handle special 'liked' playlist
        if playlist_id == 'liked':
            return self.get_spotify_liked_songs()

        tracks = []
        try:
            results = self.spotify.playlist_tracks(playlist_id, limit=100)
            
            while results:
                for item in results['items']:
                    if item and item.get('track') and item['track'].get('type') == 'track':
                        track = item['track']

                        # Safely extract track metadata with defaults
                        if not track.get('artists'):
                            artists = 'Unknown Artist'
                        else:
                            artists = ', '.join([a.get('name', 'Unknown') for a in track['artists'] if a])

                        title = track.get('name', 'Unknown Track')
                        album = track.get('album', {}).get('name', 'Unknown Album') if track.get('album') else 'Unknown Album'
                        duration_ms = track.get('duration_ms', 0)
                        track_id = track.get('id', '')

                        # Skip tracks with missing essential data
                        if not title or title == 'Unknown Track':
                            logger.warning(f"Skipping track with missing title: {track}")
                            continue

                        tracks.append(Track(
                            title=title,
                            artist=artists,
                            album=album,
                            duration_ms=duration_ms,
                            spotify_id=track_id
                        ))
                
                if results['next']:
                    self.rate_limiter.wait()
                    results = self.spotify.next(results)
                else:
                    break
            
            return tracks
            
        except Exception as e:
            logger.error(f"Failed to get playlist tracks: {e}")
            raise
    
    def search_tidal_track(self, track: Track) -> Optional[Tuple[str, int]]:
        """Enhanced track search with CJK character handling and multiple strategies"""
        if not self.tidal_auth_manager or not self.tidal_auth_manager.session:
            raise Exception("Tidal not authenticated")

        # Generate multiple search variants
        search_queries = TextProcessor.generate_search_variants(track.title, track.artist)

        best_match = None
        best_score = 0
        search_attempts = 0
        # Limit searches to 4 attempts max (reduced from 8 to minimize API calls)
        max_search_attempts = min(len(search_queries), 4)
        
        print(f"    Trying {max_search_attempts} search strategies...")
        
        for i, query in enumerate(search_queries[:max_search_attempts]):
            if len(query.strip()) < 2:
                continue
                
            try:
                search_attempts += 1
                self.rate_limiter.wait()
                
                # Debug info for CJK tracks
                if TextProcessor.has_cjk_characters(track.title) or TextProcessor.has_cjk_characters(track.artist):
                    print(f"    Strategy {i+1}: '{query}'")
                
                search_results = self.tidal_auth_manager.session.search(
                    query, [tidalapi.Track], limit=self.max_search_results
                )
                
                if not search_results or 'tracks' not in search_results:
                    continue
                
                for tidal_track in search_results['tracks']:
                    # Enhanced matching for different character sets
                    scores = self._calculate_match_scores(track, tidal_track, query)
                    combined_score = max(scores)  # Take the best score from different strategies
                    
                    # Use different thresholds for CJK vs Latin tracks
                    threshold = self.cjk_match_threshold if (TextProcessor.has_cjk_characters(track.title) or TextProcessor.has_cjk_characters(track.artist)) else self.match_threshold
                    
                    if combined_score > best_score and combined_score >= threshold:
                        best_score = combined_score
                        best_match = tidal_track.id
                        
                        # Debug info for good matches
                        if TextProcessor.has_cjk_characters(track.title) or TextProcessor.has_cjk_characters(track.artist):
                            artist_name = tidal_track.artist.name if tidal_track.artist and hasattr(tidal_track.artist, 'name') else 'Unknown'
                            track_name = tidal_track.name if hasattr(tidal_track, 'name') else 'Unknown'
                            print(f"    Match found: '{artist_name} - {track_name}' (Score: {combined_score:.1f}%)")
                
                # If we found an excellent match, stop searching
                if best_score >= 95:
                    break
                    
                # For CJK tracks, try a few more strategies even with lower scores
                if best_score >= 85 and not (TextProcessor.has_cjk_characters(track.title) or TextProcessor.has_cjk_characters(track.artist)):
                    break
                    
            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    self.rate_limiter.backoff()
                    time.sleep(self.rate_limiter.current_delay)
                    continue
                else:
                    logger.debug(f"Search error for '{query}': {e}")
                    continue
        
        if best_match:
            return best_match, int(best_score)
        return None
    
    def _calculate_match_scores(self, original_track: Track, tidal_track, search_query: str) -> List[float]:
        """Calculate multiple matching scores using different strategies"""
        scores = []

        # Safety check for None values
        if not tidal_track or not hasattr(tidal_track, 'name') or not tidal_track.name:
            return [0.0]  # Return minimal score if track data is invalid

        if not tidal_track.artist or not hasattr(tidal_track.artist, 'name') or not tidal_track.artist.name:
            # If no artist info, only match on title
            title_score = fuzz.ratio(original_track.title.lower(), tidal_track.name.lower())
            return [title_score * 0.7]  # Lower weight for title-only match

        # Original matching
        title_score = fuzz.ratio(original_track.title.lower(), tidal_track.name.lower())
        artist_score = fuzz.ratio(original_track.artist.lower(), tidal_track.artist.name.lower())
        scores.append((title_score + artist_score) / 2)
        
        # Normalized matching
        norm_orig_title = TextProcessor.normalize_text(original_track.title)
        norm_orig_artist = TextProcessor.normalize_text(original_track.artist)
        norm_tidal_title = TextProcessor.normalize_text(tidal_track.name)
        norm_tidal_artist = TextProcessor.normalize_text(tidal_track.artist.name)
        
        norm_title_score = fuzz.ratio(norm_orig_title, norm_tidal_title)
        norm_artist_score = fuzz.ratio(norm_orig_artist, norm_tidal_artist)
        scores.append((norm_title_score + norm_artist_score) / 2)
        
        # Partial matching (for when one contains the other)
        partial_title = fuzz.partial_ratio(norm_orig_title, norm_tidal_title)
        partial_artist = fuzz.partial_ratio(norm_orig_artist, norm_tidal_artist)
        scores.append((partial_title + partial_artist) / 2)
        
        # Token sort matching (handles word order differences)
        token_title = fuzz.token_sort_ratio(norm_orig_title, norm_tidal_title)
        token_artist = fuzz.token_sort_ratio(norm_orig_artist, norm_tidal_artist)
        scores.append((token_title + token_artist) / 2)
        
        # Latin-only matching for CJK tracks
        if TextProcessor.has_cjk_characters(original_track.title) or TextProcessor.has_cjk_characters(original_track.artist):
            latin_orig_title = TextProcessor.extract_latin_parts(original_track.title)
            latin_orig_artist = TextProcessor.extract_latin_parts(original_track.artist)
            
            if latin_orig_title or latin_orig_artist:
                latin_title_score = fuzz.ratio(latin_orig_title, norm_tidal_title) if latin_orig_title else 0
                latin_artist_score = fuzz.ratio(latin_orig_artist, norm_tidal_artist) if latin_orig_artist else 0
                
                if latin_orig_title and latin_orig_artist:
                    scores.append((latin_title_score + latin_artist_score) / 2)
                elif latin_orig_title:
                    scores.append(latin_title_score * 0.8)  # Slightly lower weight for title-only
                elif latin_orig_artist:
                    scores.append(latin_artist_score * 0.7)  # Lower weight for artist-only
        
        return scores
    
    def create_tidal_playlist(self, name: str, description: str = "") -> Optional[str]:
        """Create playlist with retry logic"""
        if not self.tidal_auth_manager or not self.tidal_auth_manager.session:
            raise Exception("Tidal not authenticated")
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.rate_limiter.wait()
                playlist = self.tidal_auth_manager.session.user.create_playlist(name, description)
                return playlist.id
                
            except Exception as e:
                if "429" in str(e) or "rate limit" in str(e).lower():
                    self.rate_limiter.backoff()
                    if attempt < max_retries - 1:
                        time.sleep(self.rate_limiter.current_delay)
                        continue
                
                logger.error(f"Failed to create playlist (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    return None
        
        return None
    
    def add_tracks_to_tidal_playlist(self, playlist_id: str, track_ids: List[str]) -> bool:
        """Add tracks with enhanced error handling and batch processing"""
        if not self.tidal_auth_manager or not self.tidal_auth_manager.session:
            raise Exception("Tidal not authenticated")
        
        try:
            playlist = self.tidal_auth_manager.session.playlist(playlist_id)
            
            # Add tracks in smaller batches with retry logic
            batch_size = 20  # Reduced batch size for reliability
            success_count = 0
            
            for i in range(0, len(track_ids), batch_size):
                batch = track_ids[i:i + batch_size]
                
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        self.rate_limiter.wait()
                        playlist.add(batch)
                        success_count += len(batch)
                        break
                        
                    except Exception as e:
                        if "429" in str(e) or "rate limit" in str(e).lower():
                            self.rate_limiter.backoff()
                            if attempt < max_retries - 1:
                                time.sleep(self.rate_limiter.current_delay)
                                continue
                        
                        logger.warning(f"Failed to add batch {i//batch_size + 1} (attempt {attempt + 1}): {e}")
                        if attempt == max_retries - 1:
                            logger.error(f"Permanently failed to add batch {i//batch_size + 1}")
            
            logger.info(f"Successfully added {success_count}/{len(track_ids)} tracks")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Failed to add tracks to playlist: {e}")
            return False
    
    def transfer_playlist(self, spotify_playlist_id: str,
                         new_playlist_name: str = None) -> Dict:
        """Enhanced playlist transfer with comprehensive error handling.

        Args:
            spotify_playlist_id: Playlist ID, or 'liked' for Liked Songs
            new_playlist_name: Optional custom name for Tidal playlist
        """
        print(f"\n--- Starting Enhanced Playlist Transfer ---")

        try:
            # Get Spotify playlist info - handle 'liked' specially
            if spotify_playlist_id == 'liked':
                source_name = 'Liked Songs'
                track_count = self._get_liked_songs_count()
            else:
                spotify_playlist = self.spotify.playlist(spotify_playlist_id)
                source_name = spotify_playlist['name']
                track_count = spotify_playlist['tracks']['total']

            playlist_name = new_playlist_name or f"{source_name} (from Spotify)"
            playlist_description = f"Transferred from Spotify: {source_name}"

            print(f"Transferring: {source_name}")
            print(f"Tracks: {track_count}")
            
            # Get all tracks
            tracks = self.get_spotify_playlist_tracks(spotify_playlist_id)
            print(f"Retrieved {len(tracks)} tracks from Spotify")

            # Check for empty playlist
            if not tracks:
                print("\n⚠️  Playlist is empty - nothing to transfer")
                return {
                    'success': False,
                    'error': 'Source playlist contains no tracks',
                    'total_tracks': 0,
                    'found_tracks': 0,
                    'not_found_tracks': 0
                }

            # Search for tracks on Tidal with progress updates
            found_tracks = []
            not_found_tracks = []

            print("\n--- Searching for tracks on Tidal ---")
            for i, track in enumerate(tracks, 1):
                # Show different info for CJK vs Latin tracks
                if TextProcessor.has_cjk_characters(track.title) or TextProcessor.has_cjk_characters(track.artist):
                    print(f"[{i}/{len(tracks)}] {track} (Japanese/CJK)")
                else:
                    print(f"[{i}/{len(tracks)}] {track}")
                
                try:
                    search_result = self.search_tidal_track(track)
                    if search_result:
                        tidal_id, score = search_result
                        track.tidal_id = tidal_id
                        found_tracks.append(track)
                        print(f"  ✓ Found (Score: {score}%)")
                    else:
                        not_found_tracks.append(track)
                        print(f"  ✗ Not found")
                        
                except Exception as e:
                    logger.warning(f"Search failed for {track}: {e}")
                    not_found_tracks.append(track)
                    print(f"  ✗ Search error")
                
                # Progress update every 10 tracks
                if i % 10 == 0:
                    found_rate = len(found_tracks) / i * 100
                    print(f"  Progress: {found_rate:.1f}% success rate so far")
                    
                    # Show stats for CJK vs Latin tracks
                    cjk_tracks = [t for t in tracks[:i] if TextProcessor.has_cjk_characters(t.title) or TextProcessor.has_cjk_characters(t.artist)]
                    latin_tracks = [t for t in tracks[:i] if not (TextProcessor.has_cjk_characters(t.title) or TextProcessor.has_cjk_characters(t.artist))]

                    if cjk_tracks and latin_tracks:
                        cjk_found = len([t for t in found_tracks if t in cjk_tracks])
                        latin_found = len([t for t in found_tracks if t in latin_tracks])

                        cjk_rate = (cjk_found / len(cjk_tracks) * 100) if cjk_tracks else 0
                        latin_rate = (latin_found / len(latin_tracks) * 100) if latin_tracks else 0

                        print(f"    CJK tracks: {cjk_rate:.1f}% success, Latin tracks: {latin_rate:.1f}% success")
            
            # Create Tidal playlist
            print(f"\n--- Creating Tidal playlist: {playlist_name} ---")
            tidal_playlist_id = self.create_tidal_playlist(playlist_name, playlist_description)
            
            if not tidal_playlist_id:
                return {
                    'success': False,
                    'error': 'Failed to create Tidal playlist'
                }
            
            # Add found tracks to playlist
            if found_tracks:
                print(f"Adding {len(found_tracks)} tracks to playlist...")
                track_ids = [track.tidal_id for track in found_tracks]
                success = self.add_tracks_to_tidal_playlist(tidal_playlist_id, track_ids)
                
                if not success:
                    return {
                        'success': False,
                        'error': 'Failed to add tracks to Tidal playlist'
                    }
            
            # Results summary
            results = {
                'success': True,
                'playlist_name': playlist_name,
                'tidal_playlist_id': tidal_playlist_id,
                'total_tracks': len(tracks),
                'found_tracks': len(found_tracks),
                'not_found_tracks': len(not_found_tracks),
                'found_track_list': found_tracks,
                'not_found_track_list': not_found_tracks,
                'success_rate': len(found_tracks) / len(tracks) * 100 if tracks else 0
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Playlist transfer failed: {e}")
            return {
                'success': False,
                'error': f'Transfer failed: {str(e)}'
            }
    
    def print_transfer_summary(self, results: Dict):
        """Enhanced summary with actionable information and CJK/Latin stats"""
        if not results['success']:
            print(f"\n❌ Transfer failed: {results.get('error', 'Unknown error')}")
            return
        
        print(f"\n🎉 Transfer completed!")
        print(f"Playlist: {results['playlist_name']}")
        print(f"Total tracks: {results['total_tracks']}")
        print(f"Successfully transferred: {results['found_tracks']}")
        print(f"Not found: {results['not_found_tracks']}")
        print(f"Success rate: {results['success_rate']:.1f}%")
        
        # Analyze CJK vs Latin track success rates
        all_tracks = results['found_track_list'] + results['not_found_track_list']
        cjk_tracks = [t for t in all_tracks if TextProcessor.has_cjk_characters(t.title) or TextProcessor.has_cjk_characters(t.artist)]
        latin_tracks = [t for t in all_tracks if not (TextProcessor.has_cjk_characters(t.title) or TextProcessor.has_cjk_characters(t.artist))]
        
        if cjk_tracks and latin_tracks:
            cjk_found = len([t for t in results['found_track_list'] if t in cjk_tracks])
            latin_found = len([t for t in results['found_track_list'] if t in latin_tracks])
            
            cjk_rate = cjk_found / len(cjk_tracks) * 100
            latin_rate = latin_found / len(latin_tracks) * 100
            
            print(f"\n📊 Success by language:")
            print(f"Japanese/CJK tracks: {cjk_found}/{len(cjk_tracks)} ({cjk_rate:.1f}%)")
            print(f"Latin/English tracks: {latin_found}/{len(latin_tracks)} ({latin_rate:.1f}%)")
            
            if cjk_rate < latin_rate - 20:
                print("\n💡 Tip: Japanese tracks are harder to find on Tidal. Try searching manually for missing tracks using romanized names.")
        
        if results['success_rate'] >= 90:
            print("\n🌟 Excellent transfer rate!")
        elif results['success_rate'] >= 75:
            print("\n👍 Good transfer rate!")
        elif results['success_rate'] >= 50:
            print("\n⚠️  Moderate transfer rate - some tracks missing from Tidal")
        else:
            print("\n⚠️  Low transfer rate - many tracks not available on Tidal")
        
        if results['not_found_tracks'] > 0:
            print(f"\n📝 Tracks not found on Tidal:")
            
            # Separate CJK and Latin tracks in the not found list
            not_found_cjk = [t for t in results['not_found_track_list'] if TextProcessor.has_cjk_characters(t.title) or TextProcessor.has_cjk_characters(t.artist)]
            not_found_latin = [t for t in results['not_found_track_list'] if not (TextProcessor.has_cjk_characters(t.title) or TextProcessor.has_cjk_characters(t.artist))]
            
            show_limit = 10
            shown = 0
            
            if not_found_latin:
                print("  Latin/English tracks:")
                for track in not_found_latin[:min(5, show_limit)]:
                    print(f"    • {track}")
                    shown += 1
            
            if not_found_cjk and shown < show_limit:
                print("  Japanese/CJK tracks:")
                remaining = show_limit - shown
                for track in not_found_cjk[:remaining]:
                    print(f"    • {track}")
                    shown += 1
            
            total_not_shown = len(results['not_found_track_list']) - shown
            if total_not_shown > 0:
                print(f"    ... and {total_not_shown} more")
            
            # Export missing tracks to file
            self._export_missing_tracks(results, not_found_cjk, not_found_latin)
                
            print(f"\n💡 For Japanese tracks, try searching Tidal manually using:")
            print("   - Artist name in English/romanized form")
            print("   - Alternative spellings or romanizations")
            print("   - Searching for the anime/series name instead")
    
    def _export_missing_tracks(self, results: Dict, not_found_cjk: List[Track], not_found_latin: List[Track]):
        """Export missing tracks to a text file for manual searching"""
        try:
            # Create filename based on playlist name and timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize and ensure non-empty, with length limit
            safe_name = "".join(c for c in results['playlist_name'] if c.isalnum() or c in (' ', '-', '_')).rstrip()
            if not safe_name:
                safe_name = "playlist"
            # Limit length to 100 chars (filesystem limits are typically 255)
            safe_name = safe_name[:100]
            filename = f"missing_tracks_{safe_name}_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("🎵 MISSING TRACKS FROM TIDAL TRANSFER\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Original Playlist: {results['playlist_name']}\n")
                f.write(f"Transfer Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Success Rate: {results['success_rate']:.1f}%\n")
                f.write(f"Total Missing: {results['not_found_tracks']} tracks\n\n")
                
                if not_found_latin:
                    f.write("🔤 LATIN/ENGLISH TRACKS\n")
                    f.write("-" * 30 + "\n")
                    f.write("Search suggestions:\n")
                    f.write("• Try removing parenthetical info like (TV Size), (Opening), etc.\n")
                    f.write("• Search by anime title + opening/ending\n")
                    f.write("• Look for remastered or compilation versions\n")
                    f.write("• Try artist name variations (T.M.Revolution vs TMR)\n\n")
                    
                    for i, track in enumerate(not_found_latin, 1):
                        f.write(f"{i:3}. {track.artist} - {track.title}\n")
                        f.write(f"     Album: {track.album}\n")
                        # Generate search suggestions
                        clean_title = TextProcessor.normalize_text(track.title)
                        clean_artist = TextProcessor.normalize_text(track.artist)
                        f.write(f"     Try: \"{clean_artist} {clean_title}\"\n")
                        f.write(f"     Try: \"{clean_title}\"\n")
                        if "(" in track.title or "[" in track.title:
                            simple_title = re.sub(r'[\(\[].*?[\)\]]', '', track.title).strip()
                            f.write(f"     Try: \"{track.artist} {simple_title}\"\n")
                        f.write("\n")
                
                if not_found_cjk:
                    f.write("\n🈚 JAPANESE/CJK TRACKS\n")
                    f.write("-" * 30 + "\n")
                    f.write("Search suggestions:\n")
                    f.write("• Use romanized (English) versions of artist/song names\n")
                    f.write("• Search by anime title in English\n")
                    f.write("• Try voice actor names instead of character names\n")
                    f.write("• Look for English releases or covers\n")
                    f.write("• Check if available under different romanization systems\n\n")
                    
                    for i, track in enumerate(not_found_cjk, 1):
                        f.write(f"{i:3}. {track.artist} - {track.title}\n")
                        f.write(f"     Album: {track.album}\n")
                        
                        # Extract Latin parts if any
                        latin_title = TextProcessor.extract_latin_parts(track.title)
                        latin_artist = TextProcessor.extract_latin_parts(track.artist)
                        
                        if latin_title:
                            f.write(f"     Try: \"{latin_title}\"\n")
                        if latin_artist:
                            f.write(f"     Try: \"{latin_artist}\"\n")
                        if latin_artist and latin_title:
                            f.write(f"     Try: \"{latin_artist} {latin_title}\"\n")
                        
                        # Common romanization suggestions
                        if "CV." in track.artist:
                            va_name = track.artist.split("CV.")[-1].strip().replace(")", "").replace("(", "")
                            f.write(f"     Try voice actor: \"{va_name}\"\n")
                        
                        f.write("\n")
                
                f.write("\n" + "=" * 50 + "\n")
                f.write("💡 GENERAL TIPS:\n")
                f.write("• Some tracks may be region-locked or not available on Tidal\n")
                f.write("• Try searching compilation albums like 'Anime Hits' or 'Best of...' collections\n")
                f.write("• Check if tracks are available under different artists (original vs character)\n")
                f.write("• Some anime songs might be instrumental or karaoke versions only\n")
                f.write("• Consider using other music services for region-exclusive content\n")
            
            print(f"\n📁 Missing tracks exported to: {filename}")
            
        except Exception as e:
            logger.warning(f"Failed to export missing tracks: {e}")
            print(f"\n⚠️  Could not export missing tracks to file: {e}")

    def export_playlist(self, playlist_id: str, source: str = "spotify",
                       output_format: str = "txt", output_file: str = None) -> Optional[str]:
        """Export a playlist to M3U or TXT format.

        Args:
            playlist_id: The playlist ID to export, or 'liked' for Liked Songs
            source: "spotify" or "tidal"
            output_format: "m3u" or "txt"
            output_file: Optional output filename (auto-generated if not provided)

        Returns:
            The output filename if successful, None otherwise
        """
        try:
            # Get tracks based on source
            if source == "spotify":
                if not self.spotify:
                    raise Exception("Spotify not authenticated")
                # Handle special 'liked' playlist
                if playlist_id == 'liked':
                    playlist_name = 'Liked Songs'
                else:
                    playlist_info = self.spotify.playlist(playlist_id)
                    playlist_name = playlist_info['name']
                tracks = self.get_spotify_playlist_tracks(playlist_id)
            elif source == "tidal":
                if not self.tidal_auth_manager or not self.tidal_auth_manager.session:
                    raise Exception("Tidal not authenticated")
                playlist = self.tidal_auth_manager.session.playlist(playlist_id)
                playlist_name = playlist.name
                tracks = []
                for item in playlist.tracks():
                    artist_name = item.artist.name if item.artist else "Unknown Artist"
                    album_name = item.album.name if item.album else "Unknown Album"
                    tracks.append(Track(
                        title=item.name,
                        artist=artist_name,
                        album=album_name,
                        duration_ms=item.duration * 1000 if item.duration else 0,
                        tidal_id=str(item.id)
                    ))
            else:
                raise ValueError(f"Invalid source: {source}. Use 'spotify' or 'tidal'")

            if not tracks:
                print(f"⚠️  Playlist is empty")
                return None

            # Generate filename if not provided
            if not output_file:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_name = "".join(c for c in playlist_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
                if not safe_name:
                    safe_name = "playlist"
                safe_name = safe_name[:100]
                output_file = f"{safe_name}_{source}_{timestamp}.{output_format}"

            # Write file based on format
            with open(output_file, 'w', encoding='utf-8') as f:
                if output_format == "m3u":
                    f.write("#EXTM3U\n")
                    f.write(f"#PLAYLIST:{playlist_name}\n")
                    for track in tracks:
                        duration_sec = track.duration_ms // 1000
                        f.write(f"#EXTINF:{duration_sec},{track.artist} - {track.title}\n")
                        # M3U typically has a path/URL, but we don't have that
                        # Use a comment format that's still parseable
                        f.write(f"# Album: {track.album}\n")
                else:  # txt format
                    f.write(f"Playlist: {playlist_name}\n")
                    f.write(f"Source: {source.capitalize()}\n")
                    f.write(f"Exported: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total tracks: {len(tracks)}\n")
                    f.write("=" * 50 + "\n\n")
                    for i, track in enumerate(tracks, 1):
                        f.write(f"{i:3}. {track.artist} - {track.title}\n")
                        f.write(f"     Album: {track.album}\n")
                        duration_min = track.duration_ms // 60000
                        duration_sec = (track.duration_ms % 60000) // 1000
                        f.write(f"     Duration: {duration_min}:{duration_sec:02d}\n\n")

            print(f"✓ Exported {len(tracks)} tracks to: {output_file}")
            return output_file

        except Exception as e:
            logger.error(f"Failed to export playlist: {e}")
            print(f"❌ Export failed: {e}")
            return None


def setup_logging(verbose: bool = False):
    """Configure logging level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')


def create_parser():
    """Create the argument parser."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Spotify to Tidal Playlist Transfer Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                              List Spotify playlists
  %(prog)s transfer                          Interactive transfer
  %(prog)s transfer --playlist-id ID --yes   Non-interactive transfer
  %(prog)s export --playlist-id ID           Export Spotify playlist to TXT
  %(prog)s export --playlist-id ID --format m3u --source tidal
        """
    )

    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--client-id', help='Spotify Client ID (or use SPOTIFY_CLIENT_ID env var)')
    parser.add_argument('--client-secret', help='Spotify Client Secret (or use SPOTIFY_CLIENT_SECRET env var)')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # List command
    subparsers.add_parser('list', help='List all Spotify playlists')

    # Transfer command
    transfer_parser = subparsers.add_parser('transfer', help='Transfer a playlist from Spotify to Tidal')
    transfer_parser.add_argument('--playlist-id', help='Spotify playlist ID (for non-interactive mode)')
    transfer_parser.add_argument('--name', help='Custom name for the Tidal playlist')
    transfer_parser.add_argument('--yes', '-y', action='store_true',
                                help='Skip confirmation prompt')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export a playlist to M3U or TXT file')
    export_parser.add_argument('--playlist-id', required=True, help='Playlist ID to export')
    export_parser.add_argument('--source', choices=['spotify', 'tidal'], default='spotify',
                              help='Source service (default: spotify)')
    export_parser.add_argument('--format', '-f', choices=['txt', 'm3u'], default='txt',
                              help='Output format (default: txt)')
    export_parser.add_argument('--output', '-o', help='Output filename (auto-generated if not specified)')

    return parser


def main():
    """Main entry point with CLI argument parsing."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Get credentials from args or environment
    client_id = args.client_id or os.getenv("SPOTIFY_CLIENT_ID", "")
    client_secret = args.client_secret or os.getenv("SPOTIFY_CLIENT_SECRET", "")

    if not client_id or not client_secret:
        print("⚠️  Spotify API credentials not found!")
        print("\nPlease set environment variables:")
        print("  export SPOTIFY_CLIENT_ID='your_client_id'")
        print("  export SPOTIFY_CLIENT_SECRET='your_client_secret'")
        print("\nOr use command-line flags:")
        print("  --client-id YOUR_ID --client-secret YOUR_SECRET")
        print("\nGet credentials from: https://developer.spotify.com/dashboard/applications")
        print("Make sure to add 'http://127.0.0.1:8080' as a redirect URI")
        return 1

    try:
        # Initialize transfer tool
        transfer_tool = SpotifyToTidalTransfer(
            spotify_client_id=client_id,
            spotify_client_secret=client_secret
        )

        # Handle commands
        if args.command == 'list':
            return cmd_list(transfer_tool)
        elif args.command == 'transfer':
            return cmd_transfer(transfer_tool, args)
        elif args.command == 'export':
            return cmd_export(transfer_tool, args)
        else:
            # No command - run interactive mode (legacy behavior)
            return cmd_transfer(transfer_tool, args)

    except KeyboardInterrupt:
        print("\n👋 Cancelled by user.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        return 1


def cmd_list(transfer_tool: SpotifyToTidalTransfer) -> int:
    """List all Spotify playlists."""
    if not transfer_tool.authenticate_spotify():
        print("❌ Spotify authentication failed.")
        return 1

    print("\n=== Your Spotify Playlists ===")
    playlists = transfer_tool.get_spotify_playlists()

    if not playlists:
        print("No playlists found!")
        return 0

    for i, playlist in enumerate(playlists, 1):
        print(f"{i:2}. {playlist['name']} ({playlist['tracks_count']} tracks) - {playlist['owner']}")
        print(f"    ID: {playlist['id']}")

    return 0


def cmd_transfer(transfer_tool: SpotifyToTidalTransfer, args) -> int:
    """Transfer a playlist from Spotify to Tidal."""
    # Authenticate
    print("=== Authentication ===")
    if not transfer_tool.authenticate_spotify():
        print("❌ Spotify authentication failed.")
        return 1

    if not transfer_tool.authenticate_tidal():
        print("❌ Tidal authentication failed.")
        return 1

    # Get playlist ID
    playlist_id = getattr(args, 'playlist_id', None)
    custom_name = getattr(args, 'name', None)
    skip_confirm = getattr(args, 'yes', False)

    if playlist_id:
        # Non-interactive mode
        if not skip_confirm:
            if playlist_id == 'liked':
                track_count = transfer_tool._get_liked_songs_count()
                print(f"\nPlaylist: Liked Songs ({track_count} tracks)")
            else:
                playlist_info = transfer_tool.spotify.playlist(playlist_id)
                print(f"\nPlaylist: {playlist_info['name']} ({playlist_info['tracks']['total']} tracks)")
            confirm = input("Proceed with transfer? (y/N): ")
            if confirm.lower() != 'y':
                print("Transfer cancelled.")
                return 0

        results = transfer_tool.transfer_playlist(playlist_id, custom_name)
        transfer_tool.print_transfer_summary(results)
        return 0 if results.get('success') else 1

    # Interactive mode
    print("\n=== Your Spotify Playlists ===")
    playlists = transfer_tool.get_spotify_playlists()

    if not playlists:
        print("No playlists found!")
        return 0

    for i, playlist in enumerate(playlists, 1):
        print(f"{i:2}. {playlist['name']} ({playlist['tracks_count']} tracks) - {playlist['owner']}")

    while True:
        try:
            choice = input(f"\nChoose a playlist to transfer (1-{len(playlists)}, or 'q' to quit): ")
            if choice.lower() == 'q':
                print("Goodbye!")
                return 0

            choice_num = int(choice) - 1
            if 0 <= choice_num < len(playlists):
                selected_playlist = playlists[choice_num]
                break
            print("Invalid choice! Please try again.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")

    print(f"\nYou selected: {selected_playlist['name']}")
    print(f"This playlist has {selected_playlist['tracks_count']} tracks")

    confirm = input("Proceed with transfer? (y/N): ")
    if confirm.lower() != 'y':
        print("Transfer cancelled.")
        return 0

    results = transfer_tool.transfer_playlist(selected_playlist['id'], custom_name)
    transfer_tool.print_transfer_summary(results)
    return 0 if results.get('success') else 1


def cmd_export(transfer_tool: SpotifyToTidalTransfer, args) -> int:
    """Export a playlist to file."""
    source = args.source

    # Authenticate based on source
    if source == 'spotify':
        if not transfer_tool.authenticate_spotify():
            print("❌ Spotify authentication failed.")
            return 1
    else:  # tidal
        if not transfer_tool.authenticate_tidal():
            print("❌ Tidal authentication failed.")
            return 1

    result = transfer_tool.export_playlist(
        playlist_id=args.playlist_id,
        source=source,
        output_format=args.format,
        output_file=args.output
    )

    return 0 if result else 1


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
