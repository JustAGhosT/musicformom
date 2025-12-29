# Music For Mom

A simple desktop app to download YouTube music to your USB drive. Built with Tauri for a lightweight, native experience.

## Features

- Paste a YouTube URL and download as MP3
- Auto-detects USB drives
- Shows download progress
- Adds metadata and album art
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

## Usage

1. Open the app
2. Paste a YouTube link (song, playlist, or album)
3. Select your USB drive (or browse to a folder)
4. Click "Download Music"
5. Wait for the download to complete
6. Safely eject your USB and enjoy in your car!

## Tech Stack

- [Tauri v2](https://tauri.app/) - Lightweight desktop framework
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) - YouTube downloader
- Rust backend for performance and safety
- Simple HTML/CSS/JS frontend
