# Installation Guide

Complete setup instructions for the Spotify to Tidal Playlist Transfer Tool.

## Prerequisites

Before you begin, make sure you have:

- **Python 3.8 or higher** ([Download Python](https://www.python.org/downloads/))
- **Spotify account** (Free or Premium)
- **Tidal subscription** (required to create playlists)
- **Git** (optional, for cloning the repository)

## Quick Start (5 minutes)

```bash
# 1. Clone and install
git clone https://github.com/fuyugaki/spotify-copy-to-tidal.git
cd spotify-copy-to-tidal
pip install -r requirements.txt

# 2. Set credentials (get these from Step 2 below)
export SPOTIFY_CLIENT_ID='your_client_id'
export SPOTIFY_CLIENT_SECRET='your_client_secret'

# 3. Run
python3 script.py
```

---

## Detailed Setup

### Step 1: Download the Tool

**Option A: Using Git (recommended)**
```bash
git clone https://github.com/fuyugaki/spotify-copy-to-tidal.git
cd spotify-copy-to-tidal
```

**Option B: Download ZIP**
1. Go to the [repository page](https://github.com/fuyugaki/spotify-copy-to-tidal)
2. Click the green **Code** button
3. Select **Download ZIP**
4. Extract the ZIP file and open a terminal in that folder

### Step 2: Create a Spotify Developer App

You need Spotify API credentials to access your playlists. This is free and takes ~2 minutes.

1. **Go to the Spotify Developer Dashboard**

   Open: https://developer.spotify.com/dashboard

2. **Log in** with your Spotify account

3. **Create a new app**
   - Click **Create App**
   - Fill in the form:
     - **App name**: `Playlist Transfer` (or any name you like)
     - **App description**: `Personal playlist transfer tool`
     - **Redirect URI**: `http://127.0.0.1:8080`
     - Check the agreement checkbox
   - Click **Save**

4. **Get your credentials**
   - Click on your new app
   - Click **Settings** (top right)
   - You'll see your **Client ID** - copy it
   - Click **View client secret** and copy it too

> **Important**: Keep these credentials private. Never share them or commit them to Git.

### Step 3: Install Python Dependencies

**Using a virtual environment (recommended)**:
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Without virtual environment**:
```bash
pip install -r requirements.txt
```

### Step 4: Set Environment Variables

You need to make your Spotify credentials available to the tool.

#### Linux / macOS

**Temporary (current session only)**:
```bash
export SPOTIFY_CLIENT_ID='your_client_id_here'
export SPOTIFY_CLIENT_SECRET='your_client_secret_here'
```

**Permanent** — add to your shell config file:

For **Bash** (`~/.bashrc`):
```bash
echo "export SPOTIFY_CLIENT_ID='your_client_id_here'" >> ~/.bashrc
echo "export SPOTIFY_CLIENT_SECRET='your_client_secret_here'" >> ~/.bashrc
source ~/.bashrc
```

For **Zsh** (`~/.zshrc`):
```bash
echo "export SPOTIFY_CLIENT_ID='your_client_id_here'" >> ~/.zshrc
echo "export SPOTIFY_CLIENT_SECRET='your_client_secret_here'" >> ~/.zshrc
source ~/.zshrc
```

#### Windows

**PowerShell (temporary)**:
```powershell
$env:SPOTIFY_CLIENT_ID = 'your_client_id_here'
$env:SPOTIFY_CLIENT_SECRET = 'your_client_secret_here'
```

**PowerShell (permanent)**:
```powershell
[Environment]::SetEnvironmentVariable("SPOTIFY_CLIENT_ID", "your_client_id_here", "User")
[Environment]::SetEnvironmentVariable("SPOTIFY_CLIENT_SECRET", "your_client_secret_here", "User")
```
Then restart PowerShell.

**Command Prompt (temporary)**:
```cmd
set SPOTIFY_CLIENT_ID=your_client_id_here
set SPOTIFY_CLIENT_SECRET=your_client_secret_here
```

#### Using a `.env` file (alternative)

Create a file named `.env` in the project folder:
```
SPOTIFY_CLIENT_ID=your_client_id_here
SPOTIFY_CLIENT_SECRET=your_client_secret_here
```

Then load it before running:
```bash
# Linux/macOS
export $(cat .env | xargs)

# Windows PowerShell
Get-Content .env | ForEach-Object { if ($_ -match '^(.+)=(.+)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2]) } }
```

> **Note**: Add `.env` to your `.gitignore` to avoid accidentally committing credentials.

### Step 5: Verify Installation

```bash
python3 script.py --help
```

You should see the help output with available commands.

### Step 6: First Run

```bash
python3 script.py
```

On first run:
1. **Spotify**: A browser window opens for you to authorize the app
2. **Tidal**: You'll be prompted to log in via browser or device code

After authentication, your sessions are saved for 24 hours.

---

## Platform-Specific Instructions

### macOS

If you don't have Python 3:
```bash
# Using Homebrew
brew install python3

# Or download from python.org
```

### Ubuntu/Debian Linux

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git
```

### Windows

1. Download Python from [python.org](https://www.python.org/downloads/)
2. **Important**: Check "Add Python to PATH" during installation
3. Open PowerShell or Command Prompt and verify:
   ```
   python --version
   ```

### GitHub Codespaces (Cloud)

You can run this tool entirely in the browser using GitHub Codespaces:

1. Fork this repository to your GitHub account
2. Click **Code** → **Codespaces** → **Create codespace on main**
3. Wait for the environment to build
4. In the terminal, set your credentials and run:
   ```bash
   export SPOTIFY_CLIENT_ID='your_client_id'
   export SPOTIFY_CLIENT_SECRET='your_client_secret'
   python3 script.py
   ```

> **Note**: The OAuth redirect may require port forwarding. Codespaces automatically forwards port 8080.

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | `pip install --upgrade -r requirements.txt` |
| `pip: command not found` | Use `python3 -m pip` instead of `pip` |
| `python3: command not found` | Install Python or use `python` (Windows) |
| Permission denied | Use virtual environment (see Step 3) |
| SSL certificate errors | `pip install --upgrade certifi` |
| Redirect URI mismatch | Ensure it's exactly `http://127.0.0.1:8080` in Spotify dashboard |

### Checking Your Setup

```bash
# Check Python version (need 3.8+)
python3 --version

# Check if credentials are set
echo $SPOTIFY_CLIENT_ID        # Linux/macOS
echo $env:SPOTIFY_CLIENT_ID    # Windows PowerShell

# Check installed packages
pip list | grep -E "(spotipy|tidalapi|fuzzywuzzy)"
```

### Resetting Authentication

If you're having login issues:
```bash
rm -rf ~/.spotify_tidal_config/
```

Then run the tool again to re-authenticate.

---

## Updating

To get the latest version:
```bash
cd spotify-copy-to-tidal
git pull
pip install --upgrade -r requirements.txt
```

---

## Uninstalling

```bash
# Remove the tool
rm -rf spotify-copy-to-tidal/

# Remove saved sessions
rm -rf ~/.spotify_tidal_config/

# Remove virtual environment (if used)
rm -rf venv/
```

To remove environment variables, edit your shell config file (`~/.bashrc`, `~/.zshrc`) and remove the export lines.

---

## Next Steps

- [Usage Guide](USAGE.md) — Learn how to transfer playlists
- [Configuration](CONFIGURATION.md) — Customize matching behavior
- [Troubleshooting](TROUBLESHOOTING.md) — More detailed problem solving
