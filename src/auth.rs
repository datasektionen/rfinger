use actix_web::{
    HttpMessage, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    get, web,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::get_current_timestamp;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, EmptyAdditionalClaims, IdToken, IdTokenClaims,
    IdTokenVerifier, OAuth2TokenResponse, TokenResponse,
    core::{
        CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    },
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env,
    future::{Ready, ready},
    sync::Mutex,
    time::Duration,
};
use types::{
    AuthMiddleware, AuthTokenResponse, InnerAuthMiddleware, LocalBoxFuture, OIDCData, Token,
};
use utoipa_actix_web::{scope, service_config::ServiceConfig};

use crate::error::Error;

pub mod types;

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

pub(crate) fn config() -> impl FnOnce(&mut ServiceConfig) {
    |cfg: &mut ServiceConfig| {
        cfg.service(scope("/oidc").service(callback));
    }
}

#[utoipa::path(
    tag = "auth",
    responses(
        (status = 200, description = "OIDC callback function")
    )
)]
#[get("/callback")]
async fn callback(
    query: web::Query<CallbackQuery>,
    oidc: web::Data<OIDCData>,
) -> Result<HttpResponse, Error> {
    let CallbackQuery { code, state } = query.0;
    let OIDCData {
        client,
        http_client,
        nonce,
        csrf_token,
    } = oidc.get_ref();

    check_csrf_token(csrf_token, state)?;

    let token_respones = client
        .exchange_code(AuthorizationCode::new(code))?
        .request_async(http_client)
        .await?;

    let id_token = token_respones
        .id_token()
        .ok_or(Error::InternalServerError(String::from(
            "oidc server returned no id",
        )))?;

    let id_token_verifier = client.id_token_verifier();

    let claims = id_token.claims(&id_token_verifier, nonce)?;

    check_token_hash(claims, &token_respones, id_token, id_token_verifier)?;

    let token = Token::new(claims.subject().to_string()).unwrap();

    let cookie = token.cookie()?;

    Ok(HttpResponse::TemporaryRedirect()
        .insert_header(("location", "/"))
        .cookie(cookie)
        .finish())
}

fn check_csrf_token(token: &CsrfToken, state: String) -> Result<(), Error> {
    if *token.secret() != state {
        log::error!("Invalid CSRF token on oidc callback");
        return Err(Error::BadRequest);
    }

    Ok(())
}

fn check_token_hash(
    claims: &IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
    token_respones: &AuthTokenResponse,
    id_token: &IdToken<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    id_token_verifier: IdTokenVerifier<'_, CoreJsonWebKey>,
) -> Result<(), Error> {
    let expected_access_token_hash =
        claims
            .access_token_hash()
            .ok_or(Error::InternalServerError(String::from(
                "Missing access token hash",
            )))?;

    let actual_access_token_hash = AccessTokenHash::from_token(
        token_respones.access_token(),
        id_token.signing_alg()?,
        id_token.signing_key(&id_token_verifier)?,
    )?;

    if actual_access_token_hash != *expected_access_token_hash {
        return Err(Error::InternalServerError(format!(
            "Hashes did not mach for subject {}",
            **claims.subject()
        )));
    }

    Ok(())
}

pub(crate) async fn check_token(
    token: &str,
    perm: &str,
    cache: &Mutex<HashMap<String, DateTime<Utc>>>,
) -> Result<bool, Error> {
    // Only cache tokens with get permission
    if perm == "get"
        && let Ok(lock) = cache.lock()
        && let Some(ttl) = lock.get(token)
        && *ttl > Utc::now()
    {
        return Ok(true);
    }

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/token/{}/permission/{}",
            env::var("HIVE_URL")?,
            token,
            perm
        ))
        .bearer_auth(env::var("HIVE_SECRET")?)
        .send()
        .await?
        .text()
        .await?;

    if serde_json::from_str::<bool>(&response).unwrap_or(false) {
        if perm == "get"
            && let Ok(mut lock) = cache.lock()
        {
            lock.insert(String::from(token), Utc::now() + Duration::from_secs(60));
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = InnerAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(InnerAuthMiddleware {
            service,
            auth_url: self.auth_url.clone(),
        }))
    }
}

impl<S, B> Service<ServiceRequest> for InnerAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let mut token = if let Some(token) = Token::extract_token(req.cookie("token")) {
            log::debug!("{:?}", token);
            token
        } else {
            let response = HttpResponse::TemporaryRedirect()
                .insert_header(("location", self.auth_url.clone()))
                .finish()
                .map_into_right_body();

            let (request, _pl) = req.into_parts();
            return Box::pin(async move { Ok(ServiceResponse::new(request, response)) });
        };

        req.extensions_mut().insert(token.sub.clone());

        let res = self.service.call(req);

        Box::pin(async move {
            let mut res = res.await.unwrap();

            token.exp = get_current_timestamp() + 7200;
            let cookie = token.cookie().unwrap();
            res.response_mut().add_cookie(&cookie).unwrap();

            Ok(res.map_into_left_body())
        })
    }
}
