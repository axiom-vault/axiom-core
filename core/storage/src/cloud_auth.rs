//! Shared OAuth2 token types and token management for cloud storage providers.
//!
//! All cloud providers (Google Drive, Dropbox, OneDrive) use the same pattern:
//! - A `Tokens` struct with access token, refresh token, and expiration
//! - A `TokenManager` that auto-refreshes expired tokens with double-check locking
//!
//! Provider-specific auth managers implement [`TokenRefresher`] to plug into
//! the generic [`CloudTokenManager`].

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use axiomvault_common::Result;

/// Deserialize optional OAuth secrets, treating blank strings as absent.
pub(crate) fn deserialize_optional_secret<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.filter(|secret| !secret.is_empty()))
}

/// PKCE verifier for OAuth authorization-code flows.
///
/// The verifier is generated alongside an authorization URL and must be
/// supplied when exchanging the resulting authorization code for tokens.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CloudPkceVerifier(String);

impl CloudPkceVerifier {
    /// Reconstruct a verifier from its raw secret value.
    ///
    /// Use this when an application needs to persist the verifier secret
    /// returned by [`CloudAuthorization::pkce_verifier`] across the browser
    /// authorization callback. Do not hand-roll verifier values; freshly
    /// generated authorization requests should use the verifier returned by
    /// the provider auth manager.
    pub fn new(verifier: String) -> Self {
        Self(verifier)
    }

    /// Get the verifier secret.
    ///
    /// This is primarily useful for clients that need to persist the verifier
    /// between opening the browser and receiving the OAuth callback.
    pub fn secret(&self) -> &str {
        &self.0
    }

    /// Convert into the oauth2 crate's PKCE verifier type.
    pub(crate) fn into_oauth2(mut self) -> oauth2::PkceCodeVerifier {
        oauth2::PkceCodeVerifier::new(std::mem::take(&mut self.0))
    }
}

impl From<oauth2::PkceCodeVerifier> for CloudPkceVerifier {
    fn from(verifier: oauth2::PkceCodeVerifier) -> Self {
        Self(verifier.into_secret())
    }
}

impl std::fmt::Debug for CloudPkceVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CloudPkceVerifier([REDACTED])")
    }
}

/// OAuth authorization request data for OAuth 2.1-aligned PKCE flows.
pub struct CloudAuthorization {
    /// URL the user should open to authorize the application.
    pub url: String,
    /// CSRF token that must match the callback state parameter.
    pub csrf_token: String,
    /// PKCE verifier to supply when exchanging the authorization code.
    ///
    /// Browser-based flows may store `pkce_verifier.secret()` temporarily while
    /// waiting for the OAuth callback, then reconstruct it with
    /// [`CloudPkceVerifier::new`] before calling `exchange_code`.
    pub pkce_verifier: CloudPkceVerifier,
}

impl std::fmt::Debug for CloudAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudAuthorization")
            .field("url", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .field("pkce_verifier", &self.pkce_verifier)
            .finish()
    }
}

/// OAuth2 tokens with expiration tracking.
///
/// Common across all cloud providers. Contains the access token for API
/// requests, a refresh token for renewal, and an expiration timestamp.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CloudTokens {
    /// Access token for API requests.
    pub access_token: String,
    /// Refresh token for obtaining new access tokens.
    pub refresh_token: String,
    /// When the access token expires.
    #[zeroize(skip)]
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for CloudTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudTokens")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl CloudTokens {
    /// Check if the access token is expired or about to expire.
    ///
    /// Uses a 5-minute buffer to avoid using a token that will expire
    /// during a request.
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now() + Duration::minutes(5)
    }
}

/// Trait for provider-specific token refresh logic.
///
/// Each cloud provider has its own OAuth2 endpoints and token format.
/// Implement this trait to provide the refresh behavior, then wrap it
/// in a [`CloudTokenManager`] for automatic refresh with double-check locking.
#[async_trait]
pub trait TokenRefresher: Send + Sync {
    /// Refresh an access token using the given refresh token.
    ///
    /// Returns new tokens (the refresh token itself may or may not be rotated).
    async fn refresh(&self, refresh_token: &str) -> Result<CloudTokens>;
}

/// Generic token manager with automatic refresh via double-check locking.
///
/// Wraps any [`TokenRefresher`] implementation and provides thread-safe
/// access to a valid access token, refreshing automatically when expired.
pub struct CloudTokenManager<R: TokenRefresher> {
    refresher: R,
    tokens: tokio::sync::RwLock<CloudTokens>,
}

impl<R: TokenRefresher> CloudTokenManager<R> {
    /// Create a new token manager with initial tokens.
    pub fn new(refresher: R, tokens: CloudTokens) -> Self {
        Self {
            refresher,
            tokens: tokio::sync::RwLock::new(tokens),
        }
    }

    /// Get a valid access token, refreshing if necessary.
    ///
    /// Uses double-check locking: first acquires a read lock to check
    /// expiration, then upgrades to a write lock only when refresh is needed.
    /// After acquiring the write lock, re-checks expiration to avoid
    /// redundant refreshes from concurrent callers.
    pub async fn get_access_token(&self) -> Result<String> {
        let tokens = self.tokens.read().await;
        if !tokens.is_expired() {
            return Ok(tokens.access_token.clone());
        }
        drop(tokens);

        let mut tokens = self.tokens.write().await;
        // Double-check after acquiring write lock
        if !tokens.is_expired() {
            return Ok(tokens.access_token.clone());
        }

        tracing::info!("Refreshing expired access token");
        let new_tokens = self.refresher.refresh(&tokens.refresh_token).await?;
        *tokens = new_tokens;
        Ok(tokens.access_token.clone())
    }

    /// Get the current tokens (e.g. for persistence).
    pub async fn get_tokens(&self) -> CloudTokens {
        self.tokens.read().await.clone()
    }

    /// Replace the current tokens (e.g. after manual refresh).
    pub async fn update_tokens(&self, tokens: CloudTokens) {
        *self.tokens.write().await = tokens;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_tokens_expiration() {
        let expired = CloudTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
        };
        assert!(expired.is_expired());

        let valid = CloudTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_cloud_tokens_near_expiration() {
        // Token expiring in 4 minutes should be considered expired (5 min buffer)
        let tokens = CloudTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::minutes(4),
        };
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_cloud_tokens_serialization() {
        let tokens = CloudTokens {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: CloudTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.access_token, tokens.access_token);
        assert_eq!(deserialized.refresh_token, tokens.refresh_token);
    }

    #[test]
    fn test_cloud_authorization_debug_redacts_secrets() {
        let authorization = CloudAuthorization {
            url: "https://example.test/auth?state=csrf-secret&code_challenge=challenge".to_string(),
            csrf_token: "csrf-secret".to_string(),
            pkce_verifier: CloudPkceVerifier::new("pkce-secret".to_string()),
        };

        let debug = format!("{:?}", authorization);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("csrf-secret"));
        assert!(!debug.contains("pkce-secret"));
        assert!(!debug.contains("https://example.test"));
    }

    /// Dummy refresher for testing the token manager.
    struct TestRefresher;

    #[async_trait]
    impl TokenRefresher for TestRefresher {
        async fn refresh(&self, _refresh_token: &str) -> Result<CloudTokens> {
            Ok(CloudTokens {
                access_token: "refreshed".to_string(),
                refresh_token: "new_refresh".to_string(),
                expires_at: Utc::now() + Duration::hours(1),
            })
        }
    }

    #[tokio::test]
    async fn test_cloud_token_manager_returns_valid_token() {
        let tokens = CloudTokens {
            access_token: "valid".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        let manager = CloudTokenManager::new(TestRefresher, tokens);
        let token = manager.get_access_token().await.unwrap();
        assert_eq!(token, "valid");
    }

    #[tokio::test]
    async fn test_cloud_token_manager_refreshes_expired_token() {
        let tokens = CloudTokens {
            access_token: "expired".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
        };
        let manager = CloudTokenManager::new(TestRefresher, tokens);
        let token = manager.get_access_token().await.unwrap();
        assert_eq!(token, "refreshed");
    }

    #[tokio::test]
    async fn test_cloud_token_manager_update_tokens() {
        let tokens = CloudTokens {
            access_token: "old".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        let manager = CloudTokenManager::new(TestRefresher, tokens);

        let new_tokens = CloudTokens {
            access_token: "new".to_string(),
            refresh_token: "new_refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(2),
        };
        manager.update_tokens(new_tokens).await;

        let token = manager.get_access_token().await.unwrap();
        assert_eq!(token, "new");
    }
}
