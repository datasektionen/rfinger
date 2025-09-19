use std::{
    env::VarError,
    fmt::{Display, Formatter},
};

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use aws_sdk_s3::{
    error::DisplayErrorContext,
    operation::{get_object::GetObjectError, put_object::PutObjectError},
};
use derive_more::Display;
use image::ImageError;
use openidconnect::{
    ClaimsVerificationError, ConfigurationError, HttpClientError, RequestTokenError,
    SignatureVerificationError, SigningError, StandardErrorResponse, core::CoreErrorResponseType,
    reqwest,
};
use reqwest::header::ToStrError;

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

impl From<ToStrError> for Error {
    fn from(value: ToStrError) -> Self {
        Error::InternalServerError(value.to_string())
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
        Error::InternalServerError(format!("env var error: {}", value))
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::InternalServerError(format!("failed to get data with request: {}", value))
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

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::InternalServerError(format!("{value}"))
    }
}

impl From<ImageError> for Error {
    fn from(value: ImageError) -> Self {
        Error::InternalServerError(format!("{value}"))
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::InternalServerError(format!("{value}"))
    }
}

impl From<aws_smithy_types::byte_stream::error::Error> for Error {
    fn from(value: aws_smithy_types::byte_stream::error::Error) -> Self {
        Error::InternalServerError(format!("failed to get image bytes: {value}"))
    }
}

impl From<aws_sdk_s3::error::SdkError<GetObjectError, aws_smithy_runtime_api::http::Response>>
    for Error
{
    fn from(
        value: aws_sdk_s3::error::SdkError<GetObjectError, aws_smithy_runtime_api::http::Response>,
    ) -> Self {
        Error::InternalServerError(format!(
            "failed to put object in s3: {}",
            DisplayErrorContext(value)
        ))
    }
}

impl From<aws_sdk_s3::error::SdkError<PutObjectError, aws_smithy_runtime_api::http::Response>>
    for Error
{
    fn from(
        value: aws_sdk_s3::error::SdkError<PutObjectError, aws_smithy_runtime_api::http::Response>,
    ) -> Self {
        Error::InternalServerError(format!(
            "failed to put object in s3: {}",
            DisplayErrorContext(value)
        ))
    }
}
