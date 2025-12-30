use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
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

pub struct AppState {
    auth: Mutex<AuthState>,
    config: Mutex<YouTubeConfig>,
}

// YouTube API response types
#[derive(Serialize, Deserialize, Debug)]
struct YouTubePlaylistsResponse {
    items: Vec<YouTubePlaylist>,
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
    description: String,
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Thumbnail {
    url: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct YouTubePlaylistItemsResponse {
    items: Vec<YouTubePlaylistItem>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct YouTubePlaylistItem {
    snippet: PlaylistItemSnippet,
    #[serde(rename = "contentDetails")]
    content_details: PlaylistItemContentDetails,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistItemSnippet {
    title: String,
    description: String,
    thumbnails: Option<Thumbnails>,
    #[serde(rename = "videoOwnerChannelTitle")]
    channel_title: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PlaylistItemContentDetails {
    #[serde(rename = "videoId")]
    video_id: String,
}

// Simplified types for frontend
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

// ============ yt-dlp ============

#[tauri::command]
async fn check_ytdlp() -> Result<bool, String> {
    let result = Command::new("yt-dlp").arg("--version").output().await;
    Ok(result.is_ok())
}

#[tauri::command]
async fn download_audio(
    app: tauri::AppHandle,
    url: String,
    output_dir: String,
) -> Result<String, String> {
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
            "--audio-format",
            "mp3",
            "--audio-quality",
            "0",
            "--embed-thumbnail",
            "--add-metadata",
            "--newline",
            "-o",
            &output_template,
            &url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start yt-dlp: {}. Is yt-dlp installed?", e))?;

    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

    let app_clone = app.clone();

    let stdout_handle = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
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
            }
        }
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

    let status = child
        .wait()
        .await
        .map_err(|e| format!("Process error: {}", e))?;

    let _ = stdout_handle.await;
    let errors = stderr_handle.await.unwrap_or_default();

    if status.success() {
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
    video_ids: Vec<String>,
    output_dir: String,
) -> Result<String, String> {
    let total = video_ids.len();

    for (idx, video_id) in video_ids.iter().enumerate() {
        let url = format!("https://www.youtube.com/watch?v={}", video_id);

        let _ = app.emit(
            "download-progress",
            DownloadProgress {
                status: "downloading".to_string(),
                message: format!("Downloading {}/{}", idx + 1, total),
                percent: Some((idx as f32 / total as f32) * 100.0),
            },
        );

        let output_template = PathBuf::from(&output_dir)
            .join("%(title)s.%(ext)s")
            .to_string_lossy()
            .to_string();

        let status = Command::new("yt-dlp")
            .args([
                "-x",
                "--audio-format", "mp3",
                "--audio-quality", "0",
                "--embed-thumbnail",
                "--add-metadata",
                "-o", &output_template,
                &url,
            ])
            .status()
            .await
            .map_err(|e| format!("Failed to download {}: {}", video_id, e))?;

        if !status.success() {
            log::warn!("Failed to download video: {}", video_id);
        }
    }

    let _ = app.emit(
        "download-progress",
        DownloadProgress {
            status: "complete".to_string(),
            message: format!("Downloaded {} songs!", total),
            percent: Some(100.0),
        },
    );

    Ok(format!("Downloaded {} songs!", total))
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
    Ok(())
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
        return Err("YouTube API not configured. Please add your Client ID and Secret.".to_string());
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

    // Open browser for OAuth
    open::that(&auth_url).map_err(|e| format!("Failed to open browser: {}", e))?;

    Ok("Opened browser for login".to_string())
}

#[tauri::command]
async fn wait_for_oauth_callback(state: State<'_, AppState>) -> Result<bool, String> {
    let config = {
        let c = state.config.lock().map_err(|e| e.to_string())?;
        c.clone()
    };

    // Start a local server to capture the OAuth callback
    let server = tiny_http::Server::http("127.0.0.1:8585")
        .map_err(|e| format!("Failed to start callback server: {}", e))?;

    // Wait for the callback (with timeout)
    let request = server
        .recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|e| format!("Timeout waiting for login: {}", e))?
        .ok_or("No callback received")?;

    let url = request.url().to_string();

    // Send a nice response to the browser
    let response = tiny_http::Response::from_string(
        "<html><body><h1>Login successful!</h1><p>You can close this window and return to Music For Mom.</p></body></html>"
    ).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap()
    );
    let _ = request.respond(response);

    // Extract the authorization code
    let parsed_url = url::Url::parse(&format!("http://localhost{}", url))
        .map_err(|e| format!("Failed to parse callback URL: {}", e))?;

    let code = parsed_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .ok_or("No authorization code in callback")?;

    // Exchange code for tokens
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

    // Store tokens
    let mut auth = state.auth.lock().map_err(|e| e.to_string())?;
    auth.access_token = Some(tokens.access_token);
    auth.refresh_token = tokens.refresh_token.or(auth.refresh_token.clone());
    auth.expires_at = Some(chrono_timestamp() + tokens.expires_in);

    Ok(true)
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    let mut auth = state.auth.lock().map_err(|e| e.to_string())?;
    *auth = AuthState::default();
    Ok(())
}

#[tauri::command]
async fn get_my_playlists(state: State<'_, AppState>) -> Result<Vec<PlaylistInfo>, String> {
    let access_token = get_valid_token(&state).await?;

    let client = reqwest::Client::new();
    let mut playlists = Vec::new();
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

        for item in data.items {
            playlists.push(PlaylistInfo {
                id: item.id,
                title: item.snippet.title,
                description: item.snippet.description,
                thumbnail: item
                    .snippet
                    .thumbnails
                    .and_then(|t| t.medium.or(t.default))
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
            part=snippet,contentDetails&\
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

        for item in data.items {
            videos.push(VideoInfo {
                id: item.content_details.video_id,
                title: item.snippet.title,
                channel: item.snippet.channel_title.unwrap_or_default(),
                thumbnail: item
                    .snippet
                    .thumbnails
                    .and_then(|t| t.default)
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

// Helper to get a valid access token, refreshing if needed
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

    let access_token = access_token.ok_or("Not logged in")?;

    // Check if token is expired (with 60 second buffer)
    if let Some(expires) = expires_at {
        if chrono_timestamp() > expires - 60 {
            // Token expired, try to refresh
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
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            auth: Mutex::new(AuthState::default()),
            config: Mutex::new(YouTubeConfig::default()),
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
            download_audio,
            download_videos,
            set_youtube_config,
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
