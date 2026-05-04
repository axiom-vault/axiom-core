//! OAuth2 authentication and token management for Dropbox.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use axiomvault_common::{Error, Result};

use crate::cloud_auth::{
    deserialize_optional_secret, CloudAuthorization, CloudPkceVerifier, CloudTokenManager,
    CloudTokens, TokenRefresher,
};

/// Re-export `CloudTokens` as `DropboxTokens` for backward compatibility.
pub type DropboxTokens = CloudTokens;

/// Re-export `CloudTokenManager<DropboxAuthManager>` as `DropboxTokenManager`.
pub type DropboxTokenManager = CloudTokenManager<DropboxAuthManager>;

type OAuthClient = BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

/// OAuth2 authorization endpoint.
const DROPBOX_AUTH_URL: &str = "https://www.dropbox.com/oauth2/authorize";
/// OAuth2 token endpoint.
const DROPBOX_TOKEN_URL: &str = "https://api.dropboxapi.com/oauth2/token";
/// Redirect URL for OAuth2 flow.
const REDIRECT_URL: &str = "http://localhost:8080/callback";

/// Configuration for Dropbox OAuth2 authentication.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DropboxAuthConfig {
    /// Dropbox app key (client ID).
    pub app_key: String,
    /// Optional Dropbox app secret for confidential clients.
    ///
    /// Native/public clients should use PKCE without an app secret.
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    pub app_secret: Option<String>,
    /// Redirect URL for OAuth2 callback.
    #[zeroize(skip)]
    pub redirect_url: String,
}

impl std::fmt::Debug for DropboxAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropboxAuthConfig")
            .field("app_key", &self.app_key)
            .field(
                "app_secret",
                &self.app_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

impl Default for DropboxAuthConfig {
    fn default() -> Self {
        let app_key = std::env::var("AXIOMVAULT_DROPBOX_APP_KEY").unwrap_or_default();
        let app_secret = std::env::var("AXIOMVAULT_DROPBOX_APP_SECRET")
            .ok()
            .filter(|secret| !secret.is_empty());
        Self {
            app_key,
            app_secret,
            redirect_url: REDIRECT_URL.to_string(),
        }
    }
}

impl DropboxAuthConfig {
    /// Validate that required credentials are set.
    pub fn validate(&self) -> Result<()> {
        if self.app_key.is_empty() {
            return Err(Error::InvalidInput(
                "Dropbox app key not configured. \
                 Set the AXIOMVAULT_DROPBOX_APP_KEY environment variable."
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// OAuth2 authentication manager for Dropbox.
pub struct DropboxAuthManager {
    client: OAuthClient,
    #[cfg_attr(not(test), allow(dead_code))]
    config: DropboxAuthConfig,
}

impl DropboxAuthManager {
    /// Create a new authentication manager.
    pub fn new(config: DropboxAuthConfig) -> Result<Self> {
        let mut client = BasicClient::new(ClientId::new(config.app_key.clone()))
            .set_auth_uri(
                AuthUrl::new(DROPBOX_AUTH_URL.to_string())
                    .map_err(|e| Error::InvalidInput(format!("Invalid auth URL: {}", e)))?,
            )
            .set_token_uri(
                TokenUrl::new(DROPBOX_TOKEN_URL.to_string())
                    .map_err(|e| Error::InvalidInput(format!("Invalid token URL: {}", e)))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_url.clone())
                    .map_err(|e| Error::InvalidInput(format!("Invalid redirect URL: {}", e)))?,
            );

        if let Some(app_secret) = &config.app_secret {
            client = client.set_client_secret(ClientSecret::new(app_secret.clone()));
        }

        Ok(Self { client, config })
    }

    /// Generate the authorization URL for the user to visit.
    pub fn authorization_url(&self) -> CloudAuthorization {
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token) = self
            .client
            .authorize_url(oauth2::CsrfToken::new_random)
            .add_extra_param("token_access_type", "offline")
            .set_pkce_challenge(pkce_challenge)
            .url();

        CloudAuthorization {
            url: auth_url.to_string(),
            csrf_token: csrf_token.secret().clone(),
            pkce_verifier: pkce_verifier.into(),
        }
    }

    /// Exchange an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: CloudPkceVerifier,
    ) -> Result<DropboxTokens> {
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
                Error::Authentication(
                    "No refresh token received. Ensure 'token_access_type=offline' was requested."
                        .to_string(),
                )
            })?
            .secret()
            .clone();

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| std::time::Duration::from_secs(14400));

        let expires_at =
            Utc::now() + Duration::from_std(expires_in).unwrap_or_else(|_| Duration::hours(4));

        Ok(DropboxTokens {
            access_token,
            refresh_token,
            expires_at,
        })
    }

    /// Get the current configuration (test-only).
    #[cfg(test)]
    pub(crate) fn config(&self) -> &DropboxAuthConfig {
        &self.config
    }
}

#[async_trait]
impl TokenRefresher for DropboxAuthManager {
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
        let new_refresh_token = token_result
            .refresh_token()
            .map(|t| t.secret().clone())
            .unwrap_or_else(|| refresh_token_value.clone());

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| std::time::Duration::from_secs(14400));

        let expires_at =
            Utc::now() + Duration::from_std(expires_in).unwrap_or_else(|_| Duration::hours(4));

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
        let expired = DropboxTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
        };
        assert!(expired.is_expired());

        let valid = DropboxTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_tokens_serialization() {
        let tokens = DropboxTokens {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: DropboxTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.access_token, tokens.access_token);
    }

    #[test]
    fn test_auth_config_serialization() {
        let config = DropboxAuthConfig {
            app_key: "key".to_string(),
            app_secret: None,
            redirect_url: REDIRECT_URL.to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DropboxAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.app_key, config.app_key);
    }

    #[test]
    fn test_auth_config_deserializes_empty_app_secret_as_none() {
        let config: DropboxAuthConfig = serde_json::from_value(serde_json::json!({
            "app_key": "test_key",
            "app_secret": "",
            "redirect_url": REDIRECT_URL,
        }))
        .unwrap();

        assert!(config.app_secret.is_none());
    }

    #[test]
    fn test_auth_config_debug_redacts_app_secret() {
        let config = DropboxAuthConfig {
            app_key: "test_key".to_string(),
            app_secret: Some("super-secret".to_string()),
            redirect_url: REDIRECT_URL.to_string(),
        };

        let debug = format!("{:?}", config);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_auth_manager_creation() {
        let config = DropboxAuthConfig {
            app_key: "test_key".to_string(),
            app_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };
        let manager = DropboxAuthManager::new(config).unwrap();
        assert_eq!(manager.config().app_key, "test_key");
        assert!(manager.config().app_secret.is_none());
    }

    #[test]
    fn test_config_validation_allows_empty_app_secret() {
        let config = DropboxAuthConfig {
            app_key: "test_key".to_string(),
            app_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_authorization_url() {
        let config = DropboxAuthConfig {
            app_key: "test_key".to_string(),
            app_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };
        let manager = DropboxAuthManager::new(config).unwrap();
        let authorization = manager.authorization_url();
        assert!(authorization.url.contains("dropbox.com"));
        assert!(authorization.url.contains("client_id=test_key"));
        assert!(authorization.url.contains("token_access_type=offline"));
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
