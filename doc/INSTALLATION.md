# Installation Guide

## Prerequisites

Before installing the Spotify to Tidal Playlist Transfer Tool, ensure you have:

- **Python 3.8 or higher** installed on your system
- **pip** (Python package installer)
- A **Spotify Premium account** (required for API access)
- A **Tidal subscription** (any tier)
- **Spotify Developer App credentials** (Client ID and Secret)

## Step 1: Check Python Version

Verify your Python version:

```bash
python3 --version
```

If Python 3.8+ is not installed, download it from [python.org](https://www.python.org/downloads/).

## Step 2: Clone the Repository

```bash
git clone https://github.com/yourusername/spotify-copy-to-tidal.git
cd spotify-copy-to-tidal
```

## Step 3: Install Dependencies

Install all required Python packages:

```bash
pip install -r requirements.txt
```

### Dependencies Installed

- **spotipy** - Spotify Web API wrapper
- **tidalapi** - Tidal API wrapper
- **fuzzywuzzy** - Fuzzy string matching
- **python-Levenshtein** - Performance optimization for fuzzy matching
- **requests** - HTTP library

## Step 4: Set Up Spotify API Credentials

### 4.1 Create a Spotify Developer App

1. Go to the [Spotify Developer Dashboard](https://developer.spotify.com/dashboard/applications)
2. Log in with your Spotify account
3. Click **"Create an App"**
4. Fill in the app details:
   - **App name**: Any name (e.g., "Playlist Transfer Tool")
   - **App description**: Brief description (e.g., "Transfer playlists to Tidal")
5. Accept the Terms of Service
6. Click **"Create"**

### 4.2 Configure Redirect URI

1. In your newly created app, click **"Edit Settings"**
2. Under **Redirect URIs**, add:
   ```
   http://127.0.0.1:8080
   ```
3. Click **"Add"**
4. Click **"Save"** at the bottom

### 4.3 Get Your Credentials

From your app dashboard:
- Copy your **Client ID**
- Click **"Show Client Secret"** and copy the **Client Secret**

**IMPORTANT**: Never share these credentials or commit them to version control!

## Step 5: Set Environment Variables

### On Linux/macOS

Add to your `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
export SPOTIFY_CLIENT_ID='your_client_id_here'
export SPOTIFY_CLIENT_SECRET='your_client_secret_here'
```

Then reload:
```bash
source ~/.bashrc  # or ~/.zshrc
```

### On Windows (PowerShell)

```powershell
$env:SPOTIFY_CLIENT_ID = 'your_client_id_here'
$env:SPOTIFY_CLIENT_SECRET = 'your_client_secret_here'
```

For permanent setup:
```powershell
[System.Environment]::SetEnvironmentVariable('SPOTIFY_CLIENT_ID', 'your_client_id_here', 'User')
[System.Environment]::SetEnvironmentVariable('SPOTIFY_CLIENT_SECRET', 'your_client_secret_here', 'User')
```

### On Windows (Command Prompt)

```cmd
set SPOTIFY_CLIENT_ID=your_client_id_here
set SPOTIFY_CLIENT_SECRET=your_client_secret_here
```

## Step 6: Verify Installation

Run the script to verify everything is set up:

```bash
python3 script.py
```

If configured correctly, you'll be prompted to authenticate with Spotify and Tidal.

## Troubleshooting Installation

### "ModuleNotFoundError" Error

If you see errors about missing modules:

```bash
pip install --upgrade -r requirements.txt
```

### pip Not Found

Install pip:

```bash
# Ubuntu/Debian
sudo apt-get install python3-pip

# macOS
python3 -m ensurepip --upgrade

# Windows
python -m ensurepip --upgrade
```

### Permission Errors

Use virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### SSL Certificate Errors

Update certificates:

```bash
pip install --upgrade certifi
```

## Optional: Create an Alias

For easier access, create a shell alias:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias spotify2tidal='cd /path/to/spotify-copy-to-tidal && python3 script.py'
```

Now run with:
```bash
spotify2tidal
```

## Next Steps

- See [USAGE.md](USAGE.md) for how to use the tool
- See [CONFIGURATION.md](CONFIGURATION.md) for customization options
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if you encounter issues
