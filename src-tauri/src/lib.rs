use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{Manager, State};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

// ============ Types ============

#[derive(Clone, Serialize)]
struct DownloadProgress {
    status: String,
    message: String,
    percent: Option<f32>,
}

#[derive(Serialize, Deserialize)]
struct DriveInfo {
    name: String,
    path: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct AuthState {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct YouTubeConfig {
    client_id: String,
    client_secret: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    title: String,
    url: String,
    timestamp: i64,
    output_dir: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct PersistedData {
    config: YouTubeConfig,
    auth: AuthState,
    history: Vec<HistoryItem>,
}

pub struct AppState {
    auth: Mutex<AuthState>,
    config: Mutex<YouTubeConfig>,
    history: Mutex<Vec<HistoryItem>>,
    cancel_flag: Arc<AtomicBool>,
}

// YouTube API response types
#[derive(Serialize, Deserialize, Debug)]
struct YouTubePlaylistsResponse {
    items: Option<Vec<YouTubePlaylist>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct YouTubePlaylist {
    id: String,
    snippet: PlaylistSnippet,
    #[serde(rename = "contentDetails")]
    content_details: Option<PlaylistContentDetails>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistSnippet {
    title: String,
    description: Option<String>,
    thumbnails: Option<Thumbnails>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistContentDetails {
    #[serde(rename = "itemCount")]
    item_count: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Thumbnails {
    default: Option<Thumbnail>,
    medium: Option<Thumbnail>,
    high: Option<Thumbnail>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Thumbnail {
    url: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct YouTubePlaylistItemsResponse {
    items: Option<Vec<YouTubePlaylistItem>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct YouTubePlaylistItem {
    snippet: PlaylistItemSnippet,
    #[serde(rename = "contentDetails")]
    content_details: Option<PlaylistItemContentDetails>,
    status: Option<PlaylistItemStatus>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistItemSnippet {
    title: String,
    description: Option<String>,
    thumbnails: Option<Thumbnails>,
    #[serde(rename = "videoOwnerChannelTitle")]
    channel_title: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistItemContentDetails {
    #[serde(rename = "videoId")]
    video_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistItemStatus {
    #[serde(rename = "privacyStatus")]
    privacy_status: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PlaylistInfo {
    id: String,
    title: String,
    description: String,
    thumbnail: Option<String>,
    video_count: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VideoInfo {
    id: String,
    title: String,
    channel: String,
    thumbnail: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
}

// ============ Persistence ============

fn get_config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "musicformom", "MusicForMom")
        .map(|dirs| dirs.config_dir().join("config.json"))
}

fn load_persisted_data() -> PersistedData {
    get_config_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
}

fn save_persisted_data(config: &YouTubeConfig, auth: &AuthState, history: &[HistoryItem]) {
    if let Some(path) = get_config_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = PersistedData {
            config: config.clone(),
            auth: auth.clone(),
            history: history.to_vec(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let _ = std::fs::write(path, json);
        }
    }
}

// ============ Drive Detection ============

#[tauri::command]
async fn list_drives() -> Result<Vec<DriveInfo>, String> {
    let mut drives = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/media") {
            for entry in entries.flatten() {
                if let Ok(user_entries) = std::fs::read_dir(entry.path()) {
                    for user_entry in user_entries.flatten() {
                        let path = user_entry.path();
                        if path.is_dir() {
                            drives.push(DriveInfo {
                                name: user_entry.file_name().to_string_lossy().to_string(),
                                path: path.to_string_lossy().to_string(),
                            });
                        }
                    }
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir("/mnt") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    drives.push(DriveInfo {
                        name: entry.file_name().to_string_lossy().to_string(),
                        path: path.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        for letter in b'D'..=b'Z' {
            let drive_path = format!("{}:\\", letter as char);
            let path = PathBuf::from(&drive_path);
            if path.exists() {
                drives.push(DriveInfo {
                    name: format!("Drive {}", letter as char),
                    path: drive_path,
                });
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(entries) = std::fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name != "Macintosh HD" && path.is_dir() {
                    drives.push(DriveInfo {
                        name,
                        path: path.to_string_lossy().to_string(),
                    });
                }
            }
        }
    }

    Ok(drives)
}

// ============ yt-dlp & ffmpeg ============

#[tauri::command]
async fn check_ytdlp() -> Result<bool, String> {
    let result = Command::new("yt-dlp").arg("--version").output().await;
    Ok(result.is_ok())
}

#[tauri::command]
async fn check_ffmpeg() -> Result<bool, String> {
    let result = Command::new("ffmpeg").arg("-version").output().await;
    Ok(result.is_ok())
}

#[tauri::command]
async fn update_ytdlp(app: tauri::AppHandle) -> Result<String, String> {
    let _ = app.emit(
        "download-progress",
        DownloadProgress {
            status: "updating".to_string(),
            message: "Updating yt-dlp...".to_string(),
            percent: Some(50.0),
        },
    );

    let output = Command::new("yt-dlp")
        .arg("-U")
        .output()
        .await
        .map_err(|e| format!("Failed to update yt-dlp: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let _ = app.emit(
        "download-progress",
        DownloadProgress {
            status: "complete".to_string(),
            message: "yt-dlp updated!".to_string(),
            percent: Some(100.0),
        },
    );

    if output.status.success() {
        Ok(format!("{}\n{}", stdout, stderr))
    } else {
        Err(format!("Update failed: {}", stderr))
    }
}

#[tauri::command]
async fn cancel_download(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_flag.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
async fn download_audio(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    url: String,
    output_dir: String,
) -> Result<String, String> {
    // Reset cancel flag
    state.cancel_flag.store(false, Ordering::SeqCst);
    let cancel_flag = state.cancel_flag.clone();

    let _ = app.emit(
        "download-progress",
        DownloadProgress {
            status: "starting".to_string(),
            message: "Starting download...".to_string(),
            percent: Some(0.0),
        },
    );

    let output_template = PathBuf::from(&output_dir)
        .join("%(title)s.%(ext)s")
        .to_string_lossy()
        .to_string();

    let mut child = Command::new("yt-dlp")
        .args([
            "-x",
            "--audio-format", "mp3",
            "--audio-quality", "0",
            "--embed-thumbnail",
            "--add-metadata",
            "--no-overwrites",
            "--restrict-filenames",
            "--newline",
            "--print", "%(title)s",
            "-o", &output_template,
            &url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start yt-dlp: {}. Is yt-dlp installed?", e))?;

    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

    let app_clone = app.clone();
    let cancel_flag_clone = cancel_flag.clone();

    let stdout_handle = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut title = String::new();

        while let Ok(Some(line)) = lines.next_line().await {
            if cancel_flag_clone.load(Ordering::SeqCst) {
                break;
            }

            if line.contains("[download]") {
                if let Some(percent_str) = line
                    .split_whitespace()
                    .find(|s| s.ends_with('%'))
                    .map(|s| s.trim_end_matches('%'))
                {
                    if let Ok(percent) = percent_str.parse::<f32>() {
                        let _ = app_clone.emit(
                            "download-progress",
                            DownloadProgress {
                                status: "downloading".to_string(),
                                message: format!("Downloading: {}%", percent as i32),
                                percent: Some(percent),
                            },
                        );
                    }
                }
            } else if line.contains("[ExtractAudio]") || line.contains("Destination:") {
                let _ = app_clone.emit(
                    "download-progress",
                    DownloadProgress {
                        status: "converting".to_string(),
                        message: "Converting to MP3...".to_string(),
                        percent: Some(95.0),
                    },
                );
            } else if !line.starts_with('[') && !line.is_empty() && title.is_empty() {
                title = line.clone();
            }
        }
        title
    });

    let stderr_handle = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        let mut errors = Vec::new();

        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains("ERROR") {
                errors.push(line);
            }
        }
        errors
    });

    // Check for cancellation
    let cancel_check = cancel_flag.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if cancel_check.load(Ordering::SeqCst) {
                break;
            }
        }
    });

    if cancel_flag.load(Ordering::SeqCst) {
        let _ = child.kill().await;
        let _ = app.emit(
            "download-progress",
            DownloadProgress {
                status: "cancelled".to_string(),
                message: "Download cancelled".to_string(),
                percent: Some(0.0),
            },
        );
        return Err("Download cancelled".to_string());
    }

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Process error: {}", e))?;

    let title = stdout_handle.await.unwrap_or_default();
    let errors = stderr_handle.await.unwrap_or_default();

    if cancel_flag.load(Ordering::SeqCst) {
        return Err("Download cancelled".to_string());
    }

    if status.success() {
        // Add to history
        {
            let config = state.config.lock().map_err(|e| e.to_string())?;
            let auth = state.auth.lock().map_err(|e| e.to_string())?;
            let mut history = state.history.lock().map_err(|e| e.to_string())?;

            history.insert(0, HistoryItem {
                title: if title.is_empty() { url.clone() } else { title },
                url: url.clone(),
                timestamp: chrono_timestamp(),
                output_dir: output_dir.clone(),
            });

            // Keep only last 50 items
            history.truncate(50);
            save_persisted_data(&config, &auth, &history);
        }

        let _ = app.emit(
            "download-progress",
            DownloadProgress {
                status: "complete".to_string(),
                message: "Download complete!".to_string(),
                percent: Some(100.0),
            },
        );
        Ok("Download complete!".to_string())
    } else {
        let error_msg = if errors.is_empty() {
            "Download failed - check the URL and try again".to_string()
        } else {
            errors.join("\n")
        };
        Err(error_msg)
    }
}

#[tauri::command]
async fn download_videos(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    video_ids: Vec<String>,
    output_dir: String,
) -> Result<String, String> {
    state.cancel_flag.store(false, Ordering::SeqCst);
    let cancel_flag = state.cancel_flag.clone();

    let total = video_ids.len();
    let mut successful = 0;
    let mut failed = 0;
    let mut downloaded_titles = Vec::new();

    for (idx, video_id) in video_ids.iter().enumerate() {
        if cancel_flag.load(Ordering::SeqCst) {
            let _ = app.emit(
                "download-progress",
                DownloadProgress {
                    status: "cancelled".to_string(),
                    message: format!("Cancelled after {} downloads", successful),
                    percent: Some(0.0),
                },
            );
            return Err(format!("Cancelled after {} downloads", successful));
        }

        let url = format!("https://www.youtube.com/watch?v={}", video_id);

        let _ = app.emit(
            "download-progress",
            DownloadProgress {
                status: "downloading".to_string(),
                message: format!("Downloading {}/{}...", idx + 1, total),
                percent: Some(((idx as f32) / (total as f32)) * 100.0),
            },
        );

        let output_template = PathBuf::from(&output_dir)
            .join("%(title)s.%(ext)s")
            .to_string_lossy()
            .to_string();

        let output = Command::new("yt-dlp")
            .args([
                "-x",
                "--audio-format", "mp3",
                "--audio-quality", "0",
                "--embed-thumbnail",
                "--add-metadata",
                "--no-overwrites",
                "--restrict-filenames",
                "--print", "%(title)s",
                "-o", &output_template,
                &url,
            ])
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {
                successful += 1;
                let title = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if !title.is_empty() {
                    downloaded_titles.push(title);
                }
            }
            _ => {
                failed += 1;
                log::warn!("Failed to download video: {}", video_id);
            }
        }
    }

    // Add to history
    {
        let config = state.config.lock().map_err(|e| e.to_string())?;
        let auth = state.auth.lock().map_err(|e| e.to_string())?;
        let mut history = state.history.lock().map_err(|e| e.to_string())?;

        for title in downloaded_titles {
            history.insert(0, HistoryItem {
                title,
                url: "playlist".to_string(),
                timestamp: chrono_timestamp(),
                output_dir: output_dir.clone(),
            });
        }

        history.truncate(50);
        save_persisted_data(&config, &auth, &history);
    }

    let message = if failed == 0 {
        format!("Downloaded {} songs!", successful)
    } else {
        format!("Downloaded {} songs ({} failed)", successful, failed)
    };

    let _ = app.emit(
        "download-progress",
        DownloadProgress {
            status: "complete".to_string(),
            message: message.clone(),
            percent: Some(100.0),
        },
    );

    Ok(message)
}

// ============ History ============

#[tauri::command]
async fn get_history(state: State<'_, AppState>) -> Result<Vec<HistoryItem>, String> {
    let history = state.history.lock().map_err(|e| e.to_string())?;
    Ok(history.clone())
}

#[tauri::command]
async fn clear_history(state: State<'_, AppState>) -> Result<(), String> {
    let config = state.config.lock().map_err(|e| e.to_string())?;
    let auth = state.auth.lock().map_err(|e| e.to_string())?;
    let mut history = state.history.lock().map_err(|e| e.to_string())?;

    history.clear();
    save_persisted_data(&config, &auth, &history);
    Ok(())
}

// ============ OAuth & YouTube API ============

const REDIRECT_URI: &str = "http://127.0.0.1:8585/callback";
const OAUTH_SCOPES: &str = "https://www.googleapis.com/auth/youtube.readonly";

#[tauri::command]
async fn set_youtube_config(
    state: State<'_, AppState>,
    client_id: String,
    client_secret: String,
) -> Result<(), String> {
    let mut config = state.config.lock().map_err(|e| e.to_string())?;
    config.client_id = client_id;
    config.client_secret = client_secret;

    let auth = state.auth.lock().map_err(|e| e.to_string())?;
    let history = state.history.lock().map_err(|e| e.to_string())?;
    save_persisted_data(&config, &auth, &history);
    Ok(())
}

#[tauri::command]
async fn get_youtube_config(state: State<'_, AppState>) -> Result<YouTubeConfig, String> {
    let config = state.config.lock().map_err(|e| e.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
async fn get_auth_status(state: State<'_, AppState>) -> Result<bool, String> {
    let auth = state.auth.lock().map_err(|e| e.to_string())?;
    Ok(auth.access_token.is_some())
}

#[tauri::command]
async fn start_oauth(state: State<'_, AppState>) -> Result<String, String> {
    let config = state.config.lock().map_err(|e| e.to_string())?;

    if config.client_id.is_empty() {
        return Err("YouTube API not configured. Please add your Client ID and Secret in Settings.".to_string());
    }

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
        client_id={}&\
        redirect_uri={}&\
        response_type=code&\
        scope={}&\
        access_type=offline&\
        prompt=consent",
        urlencoding::encode(&config.client_id),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(OAUTH_SCOPES)
    );

    open::that(&auth_url).map_err(|e| format!("Failed to open browser: {}", e))?;

    Ok("Opened browser for login".to_string())
}

#[tauri::command]
async fn wait_for_oauth_callback(state: State<'_, AppState>) -> Result<bool, String> {
    let config = {
        let c = state.config.lock().map_err(|e| e.to_string())?;
        c.clone()
    };

    let server = tiny_http::Server::http("127.0.0.1:8585")
        .map_err(|e| format!("Failed to start callback server: {}", e))?;

    let request = server
        .recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|e| format!("Timeout waiting for login: {}", e))?
        .ok_or("No callback received")?;

    let url = request.url().to_string();

    let response = tiny_http::Response::from_string(
        "<html><head><style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#667eea;color:white;}</style></head><body><div style='text-align:center'><h1>Login Successful!</h1><p>You can close this window.</p></div></body></html>"
    ).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap()
    );
    let _ = request.respond(response);

    let parsed_url = url::Url::parse(&format!("http://localhost{}", url))
        .map_err(|e| format!("Failed to parse callback URL: {}", e))?;

    if let Some((_, error)) = parsed_url.query_pairs().find(|(k, _)| k == "error") {
        return Err(format!("Login failed: {}", error));
    }

    let code = parsed_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .ok_or("No authorization code in callback")?;

    let client = reqwest::Client::new();
    let token_response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", &code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", REDIRECT_URI),
        ])
        .send()
        .await
        .map_err(|e| format!("Failed to exchange code: {}", e))?;

    if !token_response.status().is_success() {
        let error_text = token_response.text().await.unwrap_or_default();
        return Err(format!("Token exchange failed: {}", error_text));
    }

    let tokens: TokenResponse = token_response
        .json()
        .await
        .map_err(|e| format!("Failed to parse tokens: {}", e))?;

    let mut auth = state.auth.lock().map_err(|e| e.to_string())?;
    auth.access_token = Some(tokens.access_token);
    auth.refresh_token = tokens.refresh_token.or(auth.refresh_token.clone());
    auth.expires_at = Some(chrono_timestamp() + tokens.expires_in);

    let config = state.config.lock().map_err(|e| e.to_string())?;
    let history = state.history.lock().map_err(|e| e.to_string())?;
    save_persisted_data(&config, &auth, &history);

    Ok(true)
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    let mut auth = state.auth.lock().map_err(|e| e.to_string())?;
    *auth = AuthState::default();

    let config = state.config.lock().map_err(|e| e.to_string())?;
    let history = state.history.lock().map_err(|e| e.to_string())?;
    save_persisted_data(&config, &auth, &history);
    Ok(())
}

#[tauri::command]
async fn get_my_playlists(state: State<'_, AppState>) -> Result<Vec<PlaylistInfo>, String> {
    let access_token = get_valid_token(&state).await?;

    let client = reqwest::Client::new();
    let mut playlists = Vec::new();

    playlists.push(PlaylistInfo {
        id: "LL".to_string(),
        title: "Liked Videos".to_string(),
        description: "Your liked videos".to_string(),
        thumbnail: None,
        video_count: 0,
    });

    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://www.googleapis.com/youtube/v3/playlists?\
            part=snippet,contentDetails&\
            mine=true&\
            maxResults=50"
        );

        if let Some(token) = &page_token {
            url.push_str(&format!("&pageToken={}", token));
        }

        let response = client
            .get(&url)
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(format!("YouTube API error: {}", error));
        }

        let data: YouTubePlaylistsResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        for item in data.items.unwrap_or_default() {
            playlists.push(PlaylistInfo {
                id: item.id,
                title: item.snippet.title,
                description: item.snippet.description.unwrap_or_default(),
                thumbnail: item
                    .snippet
                    .thumbnails
                    .and_then(|t| t.medium.or(t.default).or(t.high))
                    .map(|t| t.url),
                video_count: item
                    .content_details
                    .and_then(|c| c.item_count)
                    .unwrap_or(0),
            });
        }

        page_token = data.next_page_token;
        if page_token.is_none() {
            break;
        }
    }

    Ok(playlists)
}

#[tauri::command]
async fn get_playlist_videos(
    state: State<'_, AppState>,
    playlist_id: String,
) -> Result<Vec<VideoInfo>, String> {
    let access_token = get_valid_token(&state).await?;

    let client = reqwest::Client::new();
    let mut videos = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://www.googleapis.com/youtube/v3/playlistItems?\
            part=snippet,contentDetails,status&\
            playlistId={}&\
            maxResults=50",
            playlist_id
        );

        if let Some(token) = &page_token {
            url.push_str(&format!("&pageToken={}", token));
        }

        let response = client
            .get(&url)
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(format!("YouTube API error: {}", error));
        }

        let data: YouTubePlaylistItemsResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        for item in data.items.unwrap_or_default() {
            let title = &item.snippet.title;
            if title == "Deleted video" || title == "Private video" {
                continue;
            }

            let Some(content) = item.content_details else {
                continue;
            };

            videos.push(VideoInfo {
                id: content.video_id,
                title: item.snippet.title,
                channel: item.snippet.channel_title.unwrap_or_default(),
                thumbnail: item
                    .snippet
                    .thumbnails
                    .and_then(|t| t.default.or(t.medium))
                    .map(|t| t.url),
            });
        }

        page_token = data.next_page_token;
        if page_token.is_none() {
            break;
        }
    }

    Ok(videos)
}

async fn get_valid_token(state: &State<'_, AppState>) -> Result<String, String> {
    let (access_token, refresh_token, expires_at, config) = {
        let auth = state.auth.lock().map_err(|e| e.to_string())?;
        let config = state.config.lock().map_err(|e| e.to_string())?;
        (
            auth.access_token.clone(),
            auth.refresh_token.clone(),
            auth.expires_at,
            config.clone(),
        )
    };

    let access_token = access_token.ok_or("Not logged in. Please log in first.")?;

    if let Some(expires) = expires_at {
        if chrono_timestamp() > expires - 60 {
            if let Some(refresh) = refresh_token {
                let client = reqwest::Client::new();
                let response = client
                    .post("https://oauth2.googleapis.com/token")
                    .form(&[
                        ("client_id", config.client_id.as_str()),
                        ("client_secret", config.client_secret.as_str()),
                        ("refresh_token", refresh.as_str()),
                        ("grant_type", "refresh_token"),
                    ])
                    .send()
                    .await
                    .map_err(|e| format!("Failed to refresh token: {}", e))?;

                if response.status().is_success() {
                    let tokens: TokenResponse = response
                        .json()
                        .await
                        .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

                    let mut auth = state.auth.lock().map_err(|e| e.to_string())?;
                    auth.access_token = Some(tokens.access_token.clone());
                    auth.expires_at = Some(chrono_timestamp() + tokens.expires_in);

                    let history = state.history.lock().map_err(|e| e.to_string())?;
                    save_persisted_data(&config, &auth, &history);

                    return Ok(tokens.access_token);
                }
            }
            return Err("Session expired. Please log in again.".to_string());
        }
    }

    Ok(access_token)
}

fn chrono_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ============ App Entry ============

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let persisted = load_persisted_data();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            auth: Mutex::new(persisted.auth),
            config: Mutex::new(persisted.config),
            history: Mutex::new(persisted.history),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        })
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_drives,
            check_ytdlp,
            check_ffmpeg,
            update_ytdlp,
            cancel_download,
            download_audio,
            download_videos,
            get_history,
            clear_history,
            set_youtube_config,
            get_youtube_config,
            get_auth_status,
            start_oauth,
            wait_for_oauth_callback,
            logout,
            get_my_playlists,
            get_playlist_videos,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
