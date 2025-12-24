//! Configuration for sandbox containers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Configuration for a sandbox container.
///
/// Use the builder methods to customize the sandbox behavior.
///
/// # Example
///
/// ```
/// use model_sandbox_protocol::sandbox::SandboxConfig;
/// use std::time::Duration;
///
/// let config = SandboxConfig::default()
///     .with_session_id("my-session")
///     .with_working_dir("/tmp")
///     .with_env("MY_VAR", "value")
///     .with_timeout(Duration::from_secs(60))
///     .with_hostname("my-sandbox");
/// ```
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Optional session identifier for tracking/logging.
    pub session_id: Option<String>,

    /// Working directory for command execution.
    pub working_dir: Option<PathBuf>,

    /// Environment variables to set in the sandbox.
    pub env_vars: HashMap<String, String>,

    /// Maximum time allowed for command execution.
    pub timeout: Duration,

    /// Hostname for the sandbox (UTS namespace).
    pub hostname: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            session_id: None,
            working_dir: None,
            env_vars: HashMap::new(),
            timeout: Duration::from_secs(30),
            hostname: String::from("sandbox"),
        }
    }
}

impl SandboxConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the session identifier.
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets the working directory for command execution.
    #[must_use]
    pub fn with_working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(path.into());
        self
    }

    /// Adds an environment variable.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Adds multiple environment variables from an iterator.
    #[must_use]
    pub fn with_envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env_vars.insert(k.into(), v.into());
        }
        self
    }

    /// Sets the command execution timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the sandbox hostname (UTS namespace).
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert!(config.session_id.is_none());
        assert!(config.working_dir.is_none());
        assert!(config.env_vars.is_empty());
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.hostname, "sandbox");
    }

    #[test]
    fn test_builder_chain() {
        let config = SandboxConfig::new()
            .with_session_id("test-session")
            .with_working_dir("/tmp")
            .with_env("FOO", "bar")
            .with_env("BAZ", "qux")
            .with_timeout(Duration::from_secs(60))
            .with_hostname("test-sandbox");

        assert_eq!(config.session_id, Some(String::from("test-session")));
        assert_eq!(config.working_dir, Some(PathBuf::from("/tmp")));
        assert_eq!(config.env_vars.get("FOO"), Some(&String::from("bar")));
        assert_eq!(config.env_vars.get("BAZ"), Some(&String::from("qux")));
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.hostname, "test-sandbox");
    }

    #[test]
    fn test_with_envs() {
        let vars = vec![("A", "1"), ("B", "2")];
        let config = SandboxConfig::new().with_envs(vars);

        assert_eq!(config.env_vars.get("A"), Some(&String::from("1")));
        assert_eq!(config.env_vars.get("B"), Some(&String::from("2")));
    }
}
