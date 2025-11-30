# Installation Guide

## Prerequisites

- Python 3.8+
- Spotify Premium account
- Tidal subscription
- Spotify Developer App credentials

## Setup

### 1. Install Dependencies

```bash
git clone https://github.com/yourusername/spotify-copy-to-tidal.git
cd spotify-copy-to-tidal
pip install -r requirements.txt
```

### 2. Create Spotify Developer App

1. Go to [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Click **Create an App**
3. In app settings, add redirect URI: `http://127.0.0.1:8080`
4. Copy your **Client ID** and **Client Secret**

### 3. Set Environment Variables

**Linux/macOS** (add to `~/.bashrc` or `~/.zshrc`):
```bash
export SPOTIFY_CLIENT_ID='your_client_id'
export SPOTIFY_CLIENT_SECRET='your_client_secret'
```

**Windows PowerShell**:
```powershell
$env:SPOTIFY_CLIENT_ID = 'your_client_id'
$env:SPOTIFY_CLIENT_SECRET = 'your_client_secret'
```

### 4. Verify

```bash
python3 script.py --help
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| ModuleNotFoundError | `pip install --upgrade -r requirements.txt` |
| pip not found | `python3 -m ensurepip --upgrade` |
| Permission errors | Use virtual environment: `python3 -m venv venv && source venv/bin/activate` |
| SSL certificate errors | `pip install --upgrade certifi` |
