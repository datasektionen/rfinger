use std::{
    env::VarError,
    fmt::{Display, Formatter},
};

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use derive_more::Display;
use openidconnect::{
    core::CoreErrorResponseType, reqwest, ClaimsVerificationError,
    ConfigurationError, HttpClientError, RequestTokenError,
    SignatureVerificationError, SigningError, StandardErrorResponse,
};

#[derive(Debug, Display)]
pub enum Error {
    InternalServerError(String),
    Unauthorized,
    BadRequest,
}

impl ResponseError for Error {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        match self {
            Error::InternalServerError(error) => log::error!("{}", error),
            _ => {}
        }

        HttpResponse::build(self.status_code()).body(self.to_string())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Error::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::BadRequest => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(_value: serde_json::Error) -> Self {
        Error::BadRequest
    }
}

impl From<ConfigurationError> for Error {
    fn from(value: ConfigurationError) -> Self {
        Error::InternalServerError(format!("token clinet request config error: {}", value))
    }
}

impl From<ClaimsVerificationError> for Error {
    fn from(value: ClaimsVerificationError) -> Self {
        Error::InternalServerError(format!("aquireing claims error: {}", value))
    }
}

impl From<SignatureVerificationError> for Error {
    fn from(value: SignatureVerificationError) -> Self {
        Error::InternalServerError(format!("aquireing signing algorithm: {}", value))
    }
}

impl From<SigningError> for Error {
    fn from(value: SigningError) -> Self {
        Error::InternalServerError(format!("checking hash error: {}", value))
    }
}

impl From<VarError> for Error {
    fn from(value: VarError) -> Self {
        Error::InternalServerError(format!("getting pls url error: {}", value))
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::InternalServerError(format!("failed to get data from pls: {}", value))
    }
}

impl<ER> From<RequestTokenError<HttpClientError<ER>, StandardErrorResponse<CoreErrorResponseType>>>
    for Error
where
    ER: core::error::Error + 'static,
{
    fn from(
        value: RequestTokenError<HttpClientError<ER>, StandardErrorResponse<CoreErrorResponseType>>,
    ) -> Self {
        Error::InternalServerError(format!("token request error: {}", value))
    }
}
