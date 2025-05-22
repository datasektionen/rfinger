#![warn(missing_docs)]

use actix_web::{
    HttpMessage, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    get, post, web,
};
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
    env,
    future::{Ready, ready},
};
use types::{
    AuthMiddleware, AuthTokenResponse, InnerAuthMiddleware, LocalBoxFuture, OIDCData, Token,
};

use crate::error::Error;

pub mod types;

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[get("/api/oidc/callback")]
pub async fn auth_callback(
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
        if req.path().contains("oidc") || req.path().contains("static") {
            let res = self.service.call(req);
            return Box::pin(async move { res.await.map(ServiceResponse::map_into_left_body) });
        }

        if let Some(token) = Token::extract_token(req.cookie("token")) {
            req.extensions_mut().insert(token.sub);
            let res = self.service.call(req);

            Box::pin(async move {
                let res = res.await.unwrap();

                Ok(res.map_into_left_body())
            })
        } else {
            auth_error_response(req, self.auth_url.clone())
        }
    }
}

fn auth_error_response<B>(
    req: ServiceRequest,
    auth_url: String,
) -> LocalBoxFuture<Result<ServiceResponse<EitherBody<B>>, actix_web::Error>>
where
    B: 'static,
{
    if env::var("APP_AUTH") == Ok(String::from("false")) {
        let response = HttpResponse::Unauthorized().finish().map_into_right_body();
        let (request, _pl) = req.into_parts();
        Box::pin(async move { Ok(ServiceResponse::new(request, response)) })
    } else {
        let response = HttpResponse::TemporaryRedirect()
            .insert_header(("location", auth_url))
            .finish()
            .map_into_right_body();

        let (request, _pl) = req.into_parts();
        Box::pin(async move { Ok(ServiceResponse::new(request, response)) })
    }
}
