//! Session metadata for persistence and lifecycle management.
//!
//! This module provides types for tracking session state, timestamps,
//! and other metadata that needs to be persisted to disk.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::SessionError;
use crate::session::SessionId;

/// State of a session in its lifecycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Session created but not yet used.
    #[default]
    Created,
    /// Session is actively being used.
    Active,
    /// Session has exceeded its TTL.
    Expired,
    /// Session has been cleaned up.
    Cleaned,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Active => write!(f, "active"),
            Self::Expired => write!(f, "expired"),
            Self::Cleaned => write!(f, "cleaned"),
        }
    }
}

/// Metadata for a session, persisted to disk as JSON.
///
/// This tracks the session's lifecycle, timing, and associated process information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Unique session identifier.
    pub id: SessionId,

    /// When the session was created.
    pub created_at: DateTime<Utc>,

    /// When the session will expire.
    pub expires_at: DateTime<Utc>,

    /// Last time the session was accessed.
    pub last_accessed: DateTime<Utc>,

    /// PID of the process using this session (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Current state of the session.
    pub state: SessionState,
}

impl SessionMetadata {
    /// Creates new session metadata with the given ID and TTL.
    #[must_use]
    pub fn new(id: SessionId, ttl: Duration) -> Self {
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::hours(1));

        Self {
            id,
            created_at: now,
            expires_at,
            last_accessed: now,
            pid: None,
            state: SessionState::Created,
        }
    }

    /// Loads session metadata from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if reading fails, or
    /// `SessionError::InvalidSession` if the JSON is malformed.
    pub fn load(path: &Path) -> Result<Self, SessionError> {
        let content = fs::read_to_string(path).map_err(|e| SessionError::IoError {
            context: format!("failed to read metadata file: {}", path.display()),
            source: e,
        })?;

        serde_json::from_str(&content).map_err(|e| SessionError::InvalidSession {
            reason: format!("failed to parse metadata JSON: {}", e),
        })
    }

    /// Saves session metadata to a JSON file atomically.
    ///
    /// Writes to a temporary file first, then renames to the target path
    /// to ensure atomic updates and prevent corruption on crash.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::IoError` if writing fails.
    pub fn save(&self, path: &Path) -> Result<(), SessionError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| SessionError::IoError {
            context: format!("failed to serialize metadata: {}", e),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;

        // Write to temp file first for atomic update
        let temp_path = path.with_extension("json.tmp");

        let mut file = fs::File::create(&temp_path).map_err(|e| SessionError::IoError {
            context: format!(
                "failed to create temp metadata file: {}",
                temp_path.display()
            ),
            source: e,
        })?;

        file.write_all(json.as_bytes())
            .map_err(|e| SessionError::IoError {
                context: format!("failed to write metadata: {}", temp_path.display()),
                source: e,
            })?;

        file.sync_all().map_err(|e| SessionError::IoError {
            context: "failed to sync metadata file".to_string(),
            source: e,
        })?;

        // Atomic rename
        fs::rename(&temp_path, path).map_err(|e| SessionError::IoError {
            context: format!(
                "failed to rename temp file {} to {}",
                temp_path.display(),
                path.display()
            ),
            source: e,
        })?;

        Ok(())
    }

    /// Returns true if the session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at || self.state == SessionState::Expired
    }

    /// Extends the session's expiration time from now.
    ///
    /// Also updates the last accessed timestamp.
    pub fn touch(&mut self, ttl: Duration) {
        let now = Utc::now();
        self.last_accessed = now;
        self.expires_at =
            now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::hours(1));

        // Transition from Created to Active on first touch
        if self.state == SessionState::Created {
            self.state = SessionState::Active;
        }
    }

    /// Marks the session as active with the given PID.
    pub fn set_active(&mut self, pid: u32) {
        self.state = SessionState::Active;
        self.pid = Some(pid);
        self.last_accessed = Utc::now();
    }

    /// Marks the session as expired.
    pub fn set_expired(&mut self) {
        self.state = SessionState::Expired;
        self.pid = None;
    }

    /// Marks the session as cleaned.
    pub fn set_cleaned(&mut self) {
        self.state = SessionState::Cleaned;
        self.pid = None;
    }

    /// Returns the remaining time before expiration.
    ///
    /// Returns `None` if the session has already expired.
    #[must_use]
    pub fn time_remaining(&self) -> Option<Duration> {
        let now = Utc::now();
        if now >= self.expires_at {
            None
        } else {
            (self.expires_at - now).to_std().ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_session_metadata_new() {
        let id = Uuid::new_v4();
        let ttl = Duration::from_secs(3600);
        let meta = SessionMetadata::new(id, ttl);

        assert_eq!(meta.id, id);
        assert_eq!(meta.state, SessionState::Created);
        assert!(meta.pid.is_none());
        assert!(!meta.is_expired());
        assert!(meta.time_remaining().is_some());
    }

    #[test]
    fn test_session_metadata_expired() {
        let id = Uuid::new_v4();
        let ttl = Duration::from_millis(1); // Very short TTL
        let meta = SessionMetadata::new(id, ttl);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));
        assert!(meta.is_expired());
        assert!(meta.time_remaining().is_none());
    }

    #[test]
    fn test_session_metadata_touch() {
        let id = Uuid::new_v4();
        let ttl = Duration::from_secs(1);
        let mut meta = SessionMetadata::new(id, ttl);

        let original_expires = meta.expires_at;

        // Wait a bit
        std::thread::sleep(Duration::from_millis(10));

        // Touch with longer TTL
        meta.touch(Duration::from_secs(3600));

        assert!(meta.expires_at > original_expires);
        assert_eq!(meta.state, SessionState::Active);
    }

    #[test]
    fn test_session_metadata_save_load() {
        let id = Uuid::new_v4();
        let ttl = Duration::from_secs(3600);
        let meta = SessionMetadata::new(id, ttl);

        let temp_dir = std::env::temp_dir().join("mcp-test-meta");
        std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir");
        let path = temp_dir.join("meta.json");

        // Save
        meta.save(&path).expect("failed to save metadata");

        // Load
        let loaded = SessionMetadata::load(&path).expect("failed to load metadata");

        assert_eq!(loaded.id, meta.id);
        assert_eq!(loaded.state, meta.state);
        assert_eq!(loaded.created_at, meta.created_at);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(format!("{}", SessionState::Created), "created");
        assert_eq!(format!("{}", SessionState::Active), "active");
        assert_eq!(format!("{}", SessionState::Expired), "expired");
        assert_eq!(format!("{}", SessionState::Cleaned), "cleaned");
    }

    #[test]
    fn test_session_metadata_set_active() {
        let id = Uuid::new_v4();
        let ttl = Duration::from_secs(3600);
        let mut meta = SessionMetadata::new(id, ttl);

        meta.set_active(12345);

        assert_eq!(meta.state, SessionState::Active);
        assert_eq!(meta.pid, Some(12345));
    }

    #[test]
    fn test_session_metadata_lifecycle() {
        let id = Uuid::new_v4();
        let ttl = Duration::from_secs(3600);
        let mut meta = SessionMetadata::new(id, ttl);

        // Initial state
        assert_eq!(meta.state, SessionState::Created);

        // Activate
        meta.set_active(1234);
        assert_eq!(meta.state, SessionState::Active);
        assert_eq!(meta.pid, Some(1234));

        // Expire
        meta.set_expired();
        assert_eq!(meta.state, SessionState::Expired);
        assert!(meta.pid.is_none());

        // Clean
        meta.set_cleaned();
        assert_eq!(meta.state, SessionState::Cleaned);
    }
}
