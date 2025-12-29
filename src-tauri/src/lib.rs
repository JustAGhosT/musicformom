use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use tauri::Manager;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

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

#[tauri::command]
async fn list_drives() -> Result<Vec<DriveInfo>, String> {
    let mut drives = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Check /media for mounted USB drives
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
        // Also check /mnt
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
        // Check common drive letters for removable drives
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
        // Check /Volumes for mounted drives
        if let Ok(entries) = std::fs::read_dir("/Volumes") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip Macintosh HD
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

#[tauri::command]
async fn check_ytdlp() -> Result<bool, String> {
    let result = Command::new("yt-dlp")
        .arg("--version")
        .output()
        .await;

    Ok(result.is_ok())
}

#[tauri::command]
async fn download_audio(
    app: tauri::AppHandle,
    url: String,
    output_dir: String,
) -> Result<String, String> {
    // Emit starting status
    let _ = app.emit("download-progress", DownloadProgress {
        status: "starting".to_string(),
        message: "Starting download...".to_string(),
        percent: Some(0.0),
    });

    let output_template = PathBuf::from(&output_dir)
        .join("%(title)s.%(ext)s")
        .to_string_lossy()
        .to_string();

    let mut child = Command::new("yt-dlp")
        .args([
            "-x",                           // Extract audio
            "--audio-format", "mp3",        // Convert to MP3
            "--audio-quality", "0",         // Best quality (320kbps)
            "--embed-thumbnail",            // Add album art
            "--add-metadata",               // Add metadata
            "--newline",                    // Progress on new lines
            "-o", &output_template,         // Output path
            &url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start yt-dlp: {}. Is yt-dlp installed?", e))?;

    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

    let app_clone = app.clone();

    // Read stdout for progress
    let stdout_handle = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut last_title = String::new();

        while let Ok(Some(line)) = lines.next_line().await {
            // Parse progress from yt-dlp output
            if line.contains("[download]") {
                if let Some(percent_str) = line.split_whitespace()
                    .find(|s| s.ends_with('%'))
                    .map(|s| s.trim_end_matches('%'))
                {
                    if let Ok(percent) = percent_str.parse::<f32>() {
                        let _ = app_clone.emit("download-progress", DownloadProgress {
                            status: "downloading".to_string(),
                            message: format!("Downloading: {}%", percent as i32),
                            percent: Some(percent),
                        });
                    }
                }
            } else if line.contains("[ExtractAudio]") || line.contains("Destination:") {
                let _ = app_clone.emit("download-progress", DownloadProgress {
                    status: "converting".to_string(),
                    message: "Converting to MP3...".to_string(),
                    percent: Some(95.0),
                });
            } else if line.contains("title") {
                last_title = line.clone();
            }
        }
    });

    // Also capture stderr for errors
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

    let status = child.wait().await
        .map_err(|e| format!("Process error: {}", e))?;

    let _ = stdout_handle.await;
    let errors = stderr_handle.await.unwrap_or_default();

    if status.success() {
        let _ = app.emit("download-progress", DownloadProgress {
            status: "complete".to_string(),
            message: "Download complete! 🎵".to_string(),
            percent: Some(100.0),
        });
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
