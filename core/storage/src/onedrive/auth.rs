//! OAuth2 authentication and token management for OneDrive.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use axiomvault_common::{Error, Result};

use crate::cloud_auth::{
    deserialize_optional_secret, CloudAuthorization, CloudPkceVerifier, CloudTokenManager,
    CloudTokens, TokenRefresher,
};

/// Re-export `CloudTokens` as `OneDriveTokens` for backward compatibility.
pub type OneDriveTokens = CloudTokens;

/// Re-export `CloudTokenManager<OneDriveAuthManager>` as `OneDriveTokenManager`.
pub type OneDriveTokenManager = CloudTokenManager<OneDriveAuthManager>;

type OAuthClient = BasicClient<
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

/// Microsoft identity platform authorization endpoint (consumers tenant).
const MS_AUTH_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
/// Microsoft identity platform token endpoint.
const MS_TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
/// Redirect URL for OAuth2 flow.
const REDIRECT_URL: &str = "http://localhost:8080/callback";

/// Required scopes for OneDrive file access.
const ONEDRIVE_SCOPES: &[&str] = &["Files.ReadWrite", "offline_access"];

/// Configuration for OneDrive OAuth2 authentication.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OneDriveAuthConfig {
    /// Azure AD application (client) ID.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    ///
    /// Native/public clients should use PKCE without a client secret.
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    pub client_secret: Option<String>,
    /// Redirect URL for OAuth2 callback.
    #[zeroize(skip)]
    pub redirect_url: String,
}

impl std::fmt::Debug for OneDriveAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneDriveAuthConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

impl Default for OneDriveAuthConfig {
    fn default() -> Self {
        let client_id = std::env::var("AXIOMVAULT_ONEDRIVE_CLIENT_ID").unwrap_or_default();
        let client_secret = std::env::var("AXIOMVAULT_ONEDRIVE_CLIENT_SECRET")
            .ok()
            .filter(|secret| !secret.is_empty());
        Self {
            client_id,
            client_secret,
            redirect_url: REDIRECT_URL.to_string(),
        }
    }
}

impl OneDriveAuthConfig {
    /// Validate that required credentials are set.
    pub fn validate(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(Error::InvalidInput(
                "OneDrive client ID not configured. \
                 Set the AXIOMVAULT_ONEDRIVE_CLIENT_ID environment variable."
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// OAuth2 authentication manager for OneDrive.
pub struct OneDriveAuthManager {
    client: OAuthClient,
    #[cfg_attr(not(test), allow(dead_code))]
    config: OneDriveAuthConfig,
}

impl OneDriveAuthManager {
    /// Create a new authentication manager.
    pub fn new(config: OneDriveAuthConfig) -> Result<Self> {
        let mut client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_auth_uri(
                AuthUrl::new(MS_AUTH_URL.to_string())
                    .map_err(|e| Error::InvalidInput(format!("Invalid auth URL: {}", e)))?,
            )
            .set_token_uri(
                TokenUrl::new(MS_TOKEN_URL.to_string())
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

    /// Generate the authorization URL for the user to visit.
    pub fn authorization_url(&self) -> CloudAuthorization {
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        let mut auth_request = self
            .client
            .authorize_url(oauth2::CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);

        for scope in ONEDRIVE_SCOPES {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }

        let (auth_url, csrf_token) = auth_request.url();
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
    ) -> Result<OneDriveTokens> {
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
                    "No refresh token received. Ensure 'offline_access' scope was requested."
                        .to_string(),
                )
            })?
            .secret()
            .clone();

        let expires_in = token_result
            .expires_in()
            .unwrap_or_else(|| std::time::Duration::from_secs(3600));

        let expires_at =
            Utc::now() + Duration::from_std(expires_in).unwrap_or_else(|_| Duration::hours(1));

        Ok(OneDriveTokens {
            access_token,
            refresh_token,
            expires_at,
        })
    }

    /// Get the current configuration (test-only).
    #[cfg(test)]
    pub(crate) fn config(&self) -> &OneDriveAuthConfig {
        &self.config
    }
}

#[async_trait]
impl TokenRefresher for OneDriveAuthManager {
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
        let expired = OneDriveTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
        };
        assert!(expired.is_expired());

        let valid = OneDriveTokens {
            access_token: "test".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_tokens_serialization() {
        let tokens = OneDriveTokens {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: OneDriveTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.access_token, tokens.access_token);
    }

    #[test]
    fn test_auth_config_serialization() {
        let config = OneDriveAuthConfig {
            client_id: "id".to_string(),
            client_secret: None,
            redirect_url: REDIRECT_URL.to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OneDriveAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.client_id, config.client_id);
    }

    #[test]
    fn test_auth_config_deserializes_empty_client_secret_as_none() {
        let config: OneDriveAuthConfig = serde_json::from_value(serde_json::json!({
            "client_id": "test_id",
            "client_secret": "",
            "redirect_url": REDIRECT_URL,
        }))
        .unwrap();

        assert!(config.client_secret.is_none());
    }

    #[test]
    fn test_auth_config_debug_redacts_client_secret() {
        let config = OneDriveAuthConfig {
            client_id: "test_id".to_string(),
            client_secret: Some("super-secret".to_string()),
            redirect_url: REDIRECT_URL.to_string(),
        };

        let debug = format!("{:?}", config);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_auth_manager_creation() {
        let config = OneDriveAuthConfig {
            client_id: "test_id".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };
        let manager = OneDriveAuthManager::new(config).unwrap();
        assert_eq!(manager.config().client_id, "test_id");
        assert!(manager.config().client_secret.is_none());
    }

    #[test]
    fn test_config_validation_allows_empty_client_secret() {
        let config = OneDriveAuthConfig {
            client_id: "test_id".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_authorization_url() {
        let config = OneDriveAuthConfig {
            client_id: "test_id".to_string(),
            client_secret: None,
            redirect_url: "http://localhost:8080/callback".to_string(),
        };
        let manager = OneDriveAuthManager::new(config).unwrap();
        let authorization = manager.authorization_url();
        assert!(authorization.url.contains("login.microsoftonline.com"));
        assert!(authorization.url.contains("client_id=test_id"));
        assert!(authorization.url.contains("Files.ReadWrite"));
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
