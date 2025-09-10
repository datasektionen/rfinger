use std::{env, future::Future, pin::Pin};

use actix_web::{
    FromRequest, HttpRequest,
    cookie::{Cookie, SameSite},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
};
use openidconnect::{
    Client, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce, RedirectUrl,
    RevocationErrorResponseType, StandardErrorResponse, StandardTokenIntrospectionResponse,
    StandardTokenResponse,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
        CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken, CoreTokenType,
    },
    reqwest,
};

use crate::error::Error;
use serde::{Deserialize, Serialize};

pub type OIDCClient = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    AuthTokenResponse,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, CoreTokenType>,
    CoreRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub type AuthTokenResponse = StandardTokenResponse<
    IdTokenFields<
        EmptyAdditionalClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

pub type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

#[derive(Clone)]
pub(crate) struct OIDCData {
    pub(crate) client: OIDCClient,
    pub(crate) http_client: reqwest::Client,
    // pkce_verifier: PkceCodeVerifier,
    pub(crate) nonce: Nonce,
    pub(crate) csrf_token: CsrfToken,
}

impl OIDCData {
    pub async fn get_oidc() -> (OIDCData, String) {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(env::var("OIDC_PROVIDER").expect("OIDC_PROVIDER in .env"))
                .expect("OIDC_PROVIDER to be correctly formated"),
            &http_client,
        )
        .await
        .expect("to get metadata from oidc provider");

        let client = Client::from_provider_metadata(
            provider_metadata,
            ClientId::new(env::var("OIDC_ID").expect("OIDC_ID in .env")),
            Some(ClientSecret::new(
                env::var("OIDC_SECRET").expect("OIDC_SECRET in .env"),
            )),
        )
        .set_redirect_uri(
            RedirectUrl::new(env::var("REDIRECT_URL").expect("REDIRECT_URL in .env"))
                .expect("REDIRECT_URL to be correctly formated"),
        );

        // let (pkce_challange, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            // .add_scope(Scope::new(String::from("pls_zaiko")))
            // .set_pkce_challenge(pkce_challange)
            .url();

        let oidc = OIDCData {
            client,
            http_client,
            nonce,
            // pkce_verifier,
            csrf_token,
        };

        (oidc, auth_url.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HivePermission {
    pub id: String,
    pub scope: Option<String>,
}

impl HivePermission {
    pub async fn get(token: String) -> Result<Vec<HivePermission>, Error> {
        log::debug!("getting hive permissions token {token}");
        let client = reqwest::Client::new();
        let res = client
            .get(format!(
                "{}/token/{}/permissions",
                env::var("HIVE_URL")?,
                token.as_str()
            ))
            .bearer_auth(env::var("HIVE_SECRET")?)
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str::<Vec<HivePermission>>(&res)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub sub: String,
    pub exp: u64,
}

impl Token {
    pub fn new(sub: String) -> Option<Self> {
        Some(Token {
            sub,
            exp: get_current_timestamp() + 7200,
        })
    }

    pub fn cookie(&self) -> Result<Cookie, Error> {
        let secret = EncodingKey::from_secret(env::var("APP_SECRET")?.as_bytes());

        let token = encode(&Header::default(), &self, &secret).unwrap();

        Ok(Cookie::build("token", token)
            .same_site(SameSite::Lax)
            .secure(true)
            .http_only(true)
            .path("/")
            .finish())
    }

    pub fn extract_token(cookie: Option<Cookie>) -> Option<Token> {
        let token = cookie?;

        let secret = DecodingKey::from_secret(env::var("APP_SECRET").ok()?.as_bytes());

        decode::<Token>(token.value(), &secret, &Validation::new(Algorithm::HS256))
            .ok()
            .map(|x| x.claims)
    }
}

impl FromRequest for Token {
    type Error = Error;
    type Future = LocalBoxFuture<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let cookie = req.cookie("token");
        Box::pin(async move {
            let token = Token::extract_token(cookie).ok_or(Error::Unauthorized)?;
            Ok(token)
        })
    }
}

pub struct AuthMiddleware {
    pub auth_url: String,
}

impl AuthMiddleware {
    pub fn new(auth_url: String) -> Self {
        AuthMiddleware { auth_url }
    }
}

pub struct InnerAuthMiddleware<S> {
    pub auth_url: String,
    pub service: S,
}
