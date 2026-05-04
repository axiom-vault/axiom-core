//! OAuth2 authentication and token management for Google Drive.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};

use axiomvault_common::{Error, Result};

use crate::cloud_auth::{
    deserialize_optional_secret, CloudAuthorization, CloudPkceVerifier, CloudTokenManager,
    CloudTokens, TokenRefresher,
};

/// Re-export `CloudTokens` as `Tokens` for backward compatibility.
pub type Tokens = CloudTokens;

/// Re-export `CloudTokenManager<AuthManager>` as `TokenManager`.
pub type TokenManager = CloudTokenManager<AuthManager>;

type OAuthClient = BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

/// OAuth2 authorization endpoint.
const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// OAuth2 token endpoint.
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Redirect URL for OAuth2 flow (localhost for desktop apps).
const REDIRECT_URL: &str = "http://localhost:8080/callback";

/// Google Drive OAuth2 scopes.
const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

/// Configuration for OAuth2 authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Client ID (can be overridden from default).
    pub client_id: String,
    /// Optional client secret for confidential clients.
    ///
    /// Native/public clients should use PKCE without a client secret.
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    pub client_secret: Option<String>,
    /// Redirect URL for OAuth2 callback.
    pub redirect_url: String,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        let client_id = std::env::var("AXIOMVAULT_GOOGLE_CLIENT_ID").unwrap_or_default();
        let client_secret = std::env::var("AXIOMVAULT_GOOGLE_CLIENT_SECRET")
            .ok()
            .filter(|secret| !secret.is_empty());
        Self {
            client_id,
            client_secret,
            redirect_url: REDIRECT_URL.to_string(),
        }
    }
}

impl AuthConfig {
    /// Validate that required credentials are set.
    pub fn validate(&self) -> axiomvault_common::Result<()> {
        if self.client_id.is_empty() {
            return Err(axiomvault_common::Error::InvalidInput(
                "Google OAuth2 client ID not configured. \
                 Set the AXIOMVAULT_GOOGLE_CLIENT_ID environment variable."
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// OAuth2 authentication manager for Google Drive.
pub struct AuthManager {
    client: OAuthClient,
    #[cfg_attr(not(test), allow(dead_code))]
    config: AuthConfig,
}

impl AuthManager {
    /// Create a new authentication manager.
    pub fn new(config: AuthConfig) -> Result<Self> {
        let mut client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_auth_uri(
                AuthUrl::new(GOOGLE_AUTH_URL.to_string())
                    .map_err(|e| Error::InvalidInput(format!("Invalid auth URL: {}", e)))?,
            )
            .set_token_uri(
                TokenUrl::new(GOOGLE_TOKEN_URL.to_string())
                    .map_err(|e| Error::InvalidInput(format!("Invalid token URL: {}", e)))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_url.clone())
                    .map_err(|e| Error::InvalidInput(format!("Invalid redirect URL: {}", e)))?,
            );

        if let Some(client_secret) = &config.client_secret {
            client = client.set_client_secret(ClientSecret::new(client_secret.clone()));
        }

        Ok(Self { client, config })
    }

    /// Create with default configuration (reads credentials from environment variables).
    ///
    /// Requires `AXIOMVAULT_GOOGLE_CLIENT_ID` to be set in the environment.
    /// `AXIOMVAULT_GOOGLE_CLIENT_SECRET` is optional for confidential clients.
    pub fn with_defaults() -> Result<Self> {
        let config = AuthConfig::default();
        config.validate()?;
        Self::new(config)
    }

    /// Generate the authorization URL for the user to visit.
    ///
    /// Returns the URL, CSRF token, and PKCE verifier needed for token exchange.
    pub fn authorization_url(&self) -> CloudAuthorization {
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token) = self
            .client
            .authorize_url(oauth2::CsrfToken::new_random)
            .add_scope(Scope::new(DRIVE_SCOPE.to_string()))
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent")
            .set_pkce_challenge(pkce_challenge)
            .url();

        CloudAuthorization {
            url: auth_url.to_string(),
            csrf_token: csrf_token.secret().clone(),
            pkce_verifier: pkce_verifier.into(),
        }
    }

    /// Exchange an authorization code for tokens.
    ///
    /// # Preconditions
    /// - `code` is a valid authorization code from the OAuth2 callback
    ///
    /// # Postconditions
    /// - Returns access and refresh tokens
    ///
    /// # Errors
    /// - Invalid authorization code
    /// - Network errors
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: CloudPkceVerifier,
    ) -> Result<Tokens> {
        use oauth2::AuthorizationCode;

        let http_client = oauth2::reqwest::ClientBuilder::new()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Authentication(format!("Failed to build HTTP client: {}", e)))?;

        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier.into_oauth2())
            .request_async(&http_client)
            .await
            .map_err(|e| Error::Authentication(format!("Token exchange failed: {}", e)))?;

        let access_token = token_result.access_token().secret().clone();
        let refresh_token = token_result
            .refresh_token()
            .ok_or_else(|| {
                Error::Authentication("No refresh token received. Ensure 'offline' access and 'consent' prompt were requested.".to_string())
            })?
            .secret()
            .clone();

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| std::time::Duration::from_secs(3600));

        let expires_at =
            Utc::now() + Duration::from_std(expires_in).unwrap_or_else(|_| Duration::hours(1));

        Ok(Tokens {
            access_token,
            refresh_token,
            expires_at,
        })
    }

    /// Get the current configuration (test-only).
    #[cfg(test)]
    pub(crate) fn config(&self) -> &AuthConfig {
        &self.config
    }
}

#[async_trait]
impl TokenRefresher for AuthManager {
    /// Refresh an access token using the refresh token.
    async fn refresh(&self, refresh_token: &str) -> Result<CloudTokens> {
        use oauth2::RefreshToken;

        let http_client = oauth2::reqwest::ClientBuilder::new()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Authentication(format!("Failed to build HTTP client: {}", e)))?;

        let refresh_token_value = refresh_token.to_string();
        let token_result = self
            .client
            .exchange_refresh_token(&RefreshToken::new(refresh_token_value.clone()))
            .request_async(&http_client)
            .await
            .map_err(|e| Error::Authentication(format!("Token refresh failed: {}", e)))?;

        let access_token = token_result.access_token().secret().clone();

        // Refresh tokens may or may not be returned in refresh response
        let new_refresh_token = token_result
            .refresh_token()
            .map(|t| t.secret().clone())
            .unwrap_or_else(|| refresh_token_value.clone());

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| std::time::Duration::from_secs(3600));

        let expires_at =
            Utc::now() + Duration::from_std(expires_in).unwrap_or_else(|_| Duration::hours(1));

        Ok(CloudTokens {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokens_expiration() {
        let tokens = Tokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
        };

        assert!(tokens.is_expired());

        let valid_tokens = Tokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        assert!(!valid_tokens.is_expired());
    }

    #[test]
    fn test_tokens_near_expiration() {
        // Token expiring in 4 minutes should be considered expired (5 min buffer)
        let tokens = Tokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::minutes(4),
        };

        assert!(tokens.is_expired());
    }

    #[test]
    fn test_auth_config_serialization() {
        let config = AuthConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AuthConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.client_id, config.client_id);
        assert_eq!(deserialized.redirect_url, config.redirect_url);
    }

    #[test]
    fn test_auth_config_deserializes_empty_client_secret_as_none() {
        let config: AuthConfig = serde_json::from_value(serde_json::json!({
            "client_id": "test_id",
            "client_secret": "",
            "redirect_url": REDIRECT_URL,
        }))
        .unwrap();

        assert!(config.client_secret.is_none());
    }

    #[test]
    fn test_auth_config_debug_redacts_client_secret() {
        let config = AuthConfig {
            client_id: "test_id".to_string(),
            client_secret: Some("super-secret".to_string()),
            redirect_url: REDIRECT_URL.to_string(),
        };

        let debug = format!("{:?}", config);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_tokens_serialization() {
        let tokens = Tokens {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now(),
        };

        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: Tokens = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.access_token, tokens.access_token);
        assert_eq!(deserialized.refresh_token, tokens.refresh_token);
    }

    #[test]
    fn test_auth_manager_creation() {
        let config = AuthConfig {
            client_id: "test_id".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };

        let manager = AuthManager::new(config.clone()).unwrap();
        assert_eq!(manager.config().client_id, "test_id");
        assert!(manager.config().client_secret.is_none());
    }

    #[test]
    fn test_config_validation_allows_empty_client_secret() {
        let config = AuthConfig {
            client_id: "test_id".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_authorization_url_generation() {
        let config = AuthConfig {
            client_id: "test_id".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };

        let manager = AuthManager::new(config).unwrap();
        let authorization = manager.authorization_url();

        assert!(authorization.url.contains("accounts.google.com"));
        assert!(authorization.url.contains("client_id=test_id"));
        assert!(authorization.url.contains("scope="));
        assert!(authorization.url.contains("access_type=offline"));
        assert!(authorization.url.contains("code_challenge="));
        assert!(authorization.url.contains("code_challenge_method=S256"));
        assert!(!authorization.csrf_token.is_empty());
        assert!(!authorization.pkce_verifier.secret().is_empty());

        let parsed_url = url::Url::parse(&authorization.url).unwrap();
        let code_challenge = parsed_url
            .query_pairs()
            .find_map(|(key, value)| (key == "code_challenge").then(|| value.to_string()))
            .unwrap();
        let verifier =
            oauth2::PkceCodeVerifier::new(authorization.pkce_verifier.secret().to_string());
        let expected_challenge = oauth2::PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        assert_eq!(code_challenge, expected_challenge.as_str());
    }
}
