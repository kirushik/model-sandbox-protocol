//! Session management for persistent sandbox workspaces.
//!
//! This module provides session-based isolation using OverlayFS, allowing sandboxed
//! processes to have persistent, writable filesystems while preserving changes across
//! multiple command executions within a session.
//!
//! # Architecture
//!
//! Each session creates an isolated filesystem using OverlayFS:
//! - **Lower layer**: Read-only host filesystem (`/usr`, `/bin`, `/lib`, etc.)
//! - **Upper layer**: Per-session writable layer where modifications are stored
//! - **Work directory**: Internal directory required by OverlayFS for atomic operations
//! - **Merged directory**: The unified view presented to the sandboxed process
//!
//! # Storage Layout
//!
//! Sessions are stored at `~/.mcp-sandboxes/`:
//!
//! ```text
//! ~/.mcp-sandboxes/
//! └── {session-uuid}/
//!     ├── upper/      # OverlayFS upper layer (writable changes)
//!     ├── work/       # OverlayFS work directory (internal)
//!     ├── merged/     # Mount point (sandbox root filesystem)
//!     ├── meta.json   # Session metadata (TTL, created_at, etc.)
//!     └── pid         # PID file for orphan detection
//! ```
//!
//! # Example
//!
//! ```no_run
//! use model_sandbox_protocol::session::{SessionManager, SessionConfig};
//!
//! let config = SessionConfig::default();
//! let manager = SessionManager::new(config);
//!
//! // Create a new session
//! let session = manager.create_session().unwrap();
//! println!("Session ID: {}", session.id);
//!
//! // Use the session for sandbox execution...
//!
//! // Clean up when done
//! manager.destroy_session(session.id).unwrap();
//! ```

mod lifecycle;
mod meta;
mod storage;

pub use lifecycle::SessionManager;
pub use meta::{SessionMetadata, SessionState};
pub use storage::SessionPaths;

use std::path::PathBuf;
use std::time::Duration;

/// Unique identifier for a session.
pub type SessionId = uuid::Uuid;

/// A sandbox session with persistent filesystem state.
///
/// Sessions provide isolated, persistent workspaces for sandboxed command execution.
/// Files written during execution are stored in the session's upper layer and
/// persist across multiple command executions.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier.
    pub id: SessionId,
    /// Filesystem paths for this session.
    pub paths: SessionPaths,
    /// Session metadata (timestamps, state, etc.).
    pub metadata: SessionMetadata,
}

impl Session {
    /// Creates a new session with the given ID and base directory.
    ///
    /// This is typically called by `SessionManager::create_session()`.
    /// Reserved for future direct session construction.
    #[allow(dead_code)]
    pub(crate) fn new(
        id: SessionId,
        base_dir: &std::path::Path,
        ttl: Duration,
    ) -> Result<Self, crate::error::SessionError> {
        let paths = SessionPaths::new(base_dir, id);
        let metadata = SessionMetadata::new(id, ttl);
        Ok(Self {
            id,
            paths,
            metadata,
        })
    }

    /// Returns true if this session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.metadata.is_expired()
    }

    /// Extends the session's TTL from now.
    pub fn touch(&mut self, ttl: Duration) {
        self.metadata.touch(ttl);
    }
}

/// Configuration for session management.
///
/// # Example
///
/// ```
/// use model_sandbox_protocol::session::SessionConfig;
/// use std::time::Duration;
///
/// let config = SessionConfig::default()
///     .with_ttl(Duration::from_secs(3600))
///     .with_tmp_size_mb(200);
/// ```
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Base directory for session storage.
    ///
    /// Defaults to `~/.mcp-sandboxes/`.
    pub base_dir: PathBuf,

    /// Time-to-live for sessions before expiration.
    ///
    /// Defaults to 1 hour.
    pub ttl: Duration,

    /// Size limit for tmpfs /tmp mount in megabytes.
    ///
    /// Defaults to 100 MB.
    pub tmp_size_mb: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            base_dir: storage::get_default_base_dir(),
            ttl: Duration::from_secs(3600), // 1 hour
            tmp_size_mb: 100,
        }
    }
}

impl SessionConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the base directory for session storage.
    #[must_use]
    pub fn with_base_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_dir = path.into();
        self
    }

    /// Sets the TTL for sessions.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the tmpfs size limit in megabytes.
    #[must_use]
    pub fn with_tmp_size_mb(mut self, size_mb: u32) -> Self {
        self.tmp_size_mb = size_mb;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.ttl, Duration::from_secs(3600));
        assert_eq!(config.tmp_size_mb, 100);
        assert!(config.base_dir.to_string_lossy().contains("mcp-sandboxes"));
    }

    #[test]
    fn test_session_config_builder() {
        let config = SessionConfig::new()
            .with_ttl(Duration::from_secs(7200))
            .with_tmp_size_mb(200)
            .with_base_dir("/tmp/test-sandboxes");

        assert_eq!(config.ttl, Duration::from_secs(7200));
        assert_eq!(config.tmp_size_mb, 200);
        assert_eq!(config.base_dir, PathBuf::from("/tmp/test-sandboxes"));
    }
}
