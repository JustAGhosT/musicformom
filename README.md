# Music For Mom

A simple desktop app to download YouTube music to your USB drive. Built with Tauri for a lightweight, native experience.

## Features

- **Simple Download**: Paste a YouTube URL and download as MP3
- **Playlist Browser**: Log in with Google to browse and download from your saved playlists
- **Auto-detects USB drives**: Quick buttons to save directly to your USB
- **Batch Download**: Select multiple songs from a playlist to download at once
- **High Quality**: 320kbps MP3 with metadata and album art
- Works with individual songs, playlists, and albums

## Prerequisites

### yt-dlp (Required)
This app requires yt-dlp to be installed on your system:

**Windows:**
```bash
winget install yt-dlp
```

**Mac:**
```bash
brew install yt-dlp
```

**Linux:**
```bash
sudo apt install yt-dlp
```

### FFmpeg (Required for MP3 conversion)

**Windows:**
```bash
winget install ffmpeg
```

**Mac:**
```bash
brew install ffmpeg
```

**Linux:**
```bash
sudo apt install ffmpeg
```

## Development

### Build Prerequisites

**Windows:** No additional dependencies needed.

**Mac:** No additional dependencies needed.

**Linux:**
```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

### Running in Development

```bash
npm install
npm run dev
```

### Building for Production

```bash
npm run build
```

The compiled app will be in `src-tauri/target/release/bundle/`.

## YouTube API Setup (Optional)

To browse your saved YouTube playlists, you need to set up YouTube API credentials:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable the **YouTube Data API v3**
4. Go to **APIs & Services > Credentials**
5. Click **Create Credentials > OAuth client ID**
6. Select **Desktop app** as application type
7. Copy the **Client ID** and **Client Secret**
8. In the app, go to **Settings** tab and paste your credentials

**Important:** Add `http://127.0.0.1:8585/callback` as an authorized redirect URI in your OAuth settings.

## Usage

### Simple Download
1. Open the app
2. Paste a YouTube link (song, playlist, or album)
3. Select your USB drive (or browse to a folder)
4. Click "Download Music"
5. Wait for the download to complete
6. Safely eject your USB and enjoy in your car!

### Playlist Browser
1. Set up YouTube API credentials in Settings (one-time)
2. Go to "My Playlists" tab
3. Click "Login with Google"
4. Browse your playlists and click one to open
5. Select the songs you want (or use Select All)
6. Choose destination folder
7. Click "Download Selected"

## Tech Stack

- [Tauri v2](https://tauri.app/) - Lightweight desktop framework
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) - YouTube downloader
- Rust backend for performance and safety
- Simple HTML/CSS/JS frontend
