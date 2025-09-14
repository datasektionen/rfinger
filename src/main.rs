use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile};
use actix_web::{
    App, HttpResponse, HttpServer, get,
    middleware::Logger,
    post,
    web::{self, Bytes, Redirect},
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use auth::types::{AuthMiddleware, OIDCData};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
use aws_sdk_s3::operation::put_object::{PutObjectError, PutObjectOutput};
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_runtime_api::{client::result::SdkError, http::Response};
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader};
use serde::Deserialize;
use std::io::{Cursor, Read};
use std::{env, fmt::Display};
use utoipa::{IntoParams, OpenApi};
use utoipa_actix_web::AppExt;
use utoipa_actix_web::service_config::ServiceConfig;
use utoipa_redoc::{Redoc, Servable};
use webp::{Encoder, WebPMemory};

use crate::{auth::check_token, error::Error};

mod auth;
mod error;

#[derive(Debug, Deserialize, IntoParams)]
struct GetQuery {
    quality: Option<bool>,
}

enum PathType {
    Compressed(String),
    Personal(String),
    Original(String),
    Missing,
}

impl Display for PathType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathType::Compressed(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().expect("kthid to contain at least 1 letter");
                let second = chars.next().expect("kthid to contain at least 2 letters");
                write!(f, "compressed_images/{first}/{second}/{kthid}")
            }
            PathType::Personal(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().expect("kthid to contain at least 1 letter");
                let second = chars.next().expect("kthid to contain at least 2 letters");
                write!(f, "personal_images/{first}/{second}/{kthid}")
            }
            PathType::Original(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().expect("kthid to contain at least 1 letter");
                let second = chars.next().expect("kthid to contain at least 2 letters");
                write!(f, "original_images/{first}/{second}/{kthid}")
            }
            PathType::Missing => write!(f, "missing.svg"),
        }
    }
}

struct Client {
    s3_client: aws_sdk_s3::Client,
}

impl Client {
    async fn new() -> Self {
        let config = aws_config::load_defaults(BehaviorVersion::latest())
            .await
            .into_builder()
            // .endpoint_url("http://localhost:9090")
            .region(Region::new("eu-west-1"))
            .build();

        let config = aws_sdk_s3::config::Builder::from(&config)
            // .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);

        Client { s3_client: client }
    }
    async fn get_image(&self, kthid: &str, quality: bool) -> Result<(Bytes, String), Error> {
        let mut key;

        if !quality {
            key = PathType::Compressed(kthid.to_string());

            if let Ok(image) = self.get_object(&key.to_string()).await {
                let image_bytes = image.body.collect().await?.into_bytes();
                let mime_type = image
                    .content_type
                    .clone()
                    .ok_or(Error::InternalServerError(String::from(
                        "image has no mime type",
                    )))?;
                return Ok((image_bytes, mime_type));
            }
        }

        key = PathType::Personal(kthid.to_string());

        if let Ok(image) = self.get_object(&key.to_string()).await {
            let image_bytes = image.body.collect().await?.into_bytes();
            let mime_type = image
                .content_type
                .clone()
                .ok_or(Error::InternalServerError(String::from(
                    "image has no mime type",
                )))?;
            if !quality {
                let compressed = process_image(image_bytes.to_vec(), &mime_type)?;
                self.put_object(
                    PathType::Compressed(kthid.to_string()),
                    compressed.clone(),
                    "image/webp",
                )
                .await?;

                return Ok((Bytes::from(compressed), String::from("image/webp")));
            } else {
                return Ok((image_bytes, mime_type));
            }
        }

        key = PathType::Original(kthid.to_string());

        if let Ok(image) = self.get_object(&key.to_string()).await {
            let image_bytes = image.body.collect().await?.into_bytes();
            let mime_type = image
                .content_type
                .clone()
                .ok_or(Error::InternalServerError(String::from(
                    "image has no mime type",
                )))?;
            if !quality {
                let compressed = process_image(image_bytes.to_vec(), &mime_type)?;
                self.put_object(
                    PathType::Compressed(kthid.to_string()),
                    compressed.clone(),
                    "image/webp",
                )
                .await?;

                return Ok((Bytes::from(compressed), mime_type));
            } else {
                return Ok((image_bytes, mime_type));
            }
        }

        key = PathType::Missing;

        let image = self.get_object(&key.to_string()).await?;
        let image_bytes = image.body.collect().await?.into_bytes();
        let mime_type = image
            .content_type
            .clone()
            .ok_or(Error::InternalServerError(String::from(
                "image has no mime type",
            )))?;
        Ok((image_bytes, mime_type))
    }

    async fn get_object(
        &self,
        key: &str,
    ) -> Result<GetObjectOutput, SdkError<GetObjectError, Response>> {
        self.s3_client
            .get_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(key.to_string())
            .send()
            .await
    }

    async fn put_image(
        &self,
        path: PathType,
        kthid: &str,
        image_bytes: Vec<u8>,
        mime_type: &str,
    ) -> Result<PutObjectOutput, Error> {
        self.put_object(path, image_bytes.clone(), &mime_type)
            .await?;

        let image_bytes = process_image(image_bytes, mime_type)?;

        Ok(self
            .put_object(
                PathType::Compressed(kthid.to_string()),
                image_bytes,
                "image/webp",
            )
            .await?)
    }

    async fn put_object(
        &self,
        path: PathType,
        image_bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<PutObjectOutput, SdkError<PutObjectError, Response>> {
        self.s3_client
            .put_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(path.to_string())
            .body(ByteStream::from(image_bytes))
            .content_type(content_type)
            .send()
            .await
    }
}

fn get_bytes(image: &TempFile) -> Result<Vec<u8>, std::io::Error> {
    image
        .file
        .as_file()
        .bytes()
        .map(|x| x)
        .collect::<Result<Vec<u8>, std::io::Error>>()
}

fn process_image(image_bytes: Vec<u8>, mime_type: &str) -> Result<Vec<u8>, Error> {
    let img_format = ImageFormat::from_mime_type(mime_type).ok_or(Error::InternalServerError(
        String::from("incorrect mime type: {mime_type}"),
    ))?;

    let image = ImageReader::with_format(Cursor::new(image_bytes), img_format).decode()?;

    let image = image.resize(480, 480, FilterType::Lanczos3);

    // Make webp::Encoder from DynamicImage.
    let encoder: Encoder = Encoder::from_image(&image)?;

    // Encode image into WebPMemory.
    let encoded_webp: WebPMemory = encoder.encode(65f32);

    Ok(encoded_webp
        .bytes()
        .map(|x| x)
        .collect::<Result<Vec<u8>, std::io::Error>>()?)
}

#[derive(OpenApi)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let client = web::Data::new(Client::new().await);
    let (oidc, auth_url) = OIDCData::get_oidc().await;
    let oidc = web::Data::new(oidc);

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .into_utoipa_app()
            .map(|app| {
                app.wrap(Logger::default())
                    .wrap(cors)
                    .app_data(client.clone())
                    .app_data(oidc.clone())
            })
            .service(utoipa_actix_web::scope("/auth").configure(auth::config()))
            .service(utoipa_actix_web::scope("/api").configure(config_api()))
            .service(
                utoipa_actix_web::scope("")
                    .configure(config_interactie())
                    .map(|app| {
                        app.service(index)
                            .wrap(AuthMiddleware::new(auth_url.clone()))
                    }),
            )
            .openapi_service(|api| Redoc::with_url("/docs/api", api))
            .into_app()
    })
    .bind((
        "0.0.0.0",
        env::var("PORT")
            .expect("port env variable")
            .parse::<u16>()
            .expect("port to number"),
    ))?
    .run()
    .await
}

fn config_interactie() -> impl FnOnce(&mut ServiceConfig) {
    |cfg: &mut ServiceConfig| {
        cfg.service(me).service(upload_interactive);
    }
}

fn config_api() -> impl FnOnce(&mut ServiceConfig) {
    |cfg: &mut ServiceConfig| {
        cfg.service(get).service(upload).service(nollan);
    }
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    image: TempFile,
}

#[get("/")]
async fn index() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("index.html")?)
}

#[utoipa::path(tag = "interactive")]
#[post("/")]
async fn upload_interactive(
    s3: web::Data<Client>,
    kthid: web::ReqData<String>,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<Redirect, Error> {
    s3.put_image(
        PathType::Personal(kthid.to_string()),
        kthid.as_ref(),
        get_bytes(&form.image)?,
        &form
            .image
            .content_type
            .ok_or(Error::BadRequest)?
            .to_string(),
    )
    .await?;

    Ok(Redirect::to("/").see_other())
}

#[utoipa::path(tag = "interactive")]
#[get("/me")]
async fn me(
    s3: web::Data<Client>,
    id: web::ReqData<String>,
    query: web::Query<GetQuery>,
) -> HttpResponse {
    let response = s3
        .get_image(&id.to_string(), query.quality.unwrap_or(false))
        .await;

    if let Ok((bytes, mime_type)) = response {
        HttpResponse::Ok().content_type(mime_type).body(bytes)
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

#[utoipa::path(tag = "api")]
#[get("/{kthid}")]
async fn get(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    query: web::Query<GetQuery>,
    auth: BearerAuth,
) -> Result<HttpResponse, Error> {
    if check_token(auth.token(), "get").await? {
        return Err(Error::Unauthorized);
    }

    let (bytes, mime_type) = s3
        .get_image(&kthid.to_string(), query.quality.unwrap_or(false))
        .await?;

    Ok(HttpResponse::Ok().content_type(mime_type).body(bytes))
}

#[utoipa::path(tag = "api")]
#[post("/{kthid}")]
async fn upload(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    auth: BearerAuth,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<HttpResponse, Error> {
    if check_token(auth.token(), "upload").await? {
        return Err(Error::Unauthorized);
    }

    s3.put_image(
        PathType::Personal(kthid.to_string()),
        kthid.as_ref(),
        get_bytes(&form.image)?,
        &form
            .image
            .content_type
            .ok_or(Error::BadRequest)?
            .to_string(),
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}

#[utoipa::path(tag = "api")]
#[post("/nollan/{kthid}")]
async fn nollan(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    auth: BearerAuth,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<HttpResponse, Error> {
    if check_token(auth.token(), "nollan").await? {
        return Err(Error::Unauthorized);
    }

    s3.put_image(
        PathType::Original(kthid.to_string()),
        kthid.as_ref(),
        get_bytes(&form.image)?,
        &form
            .image
            .content_type
            .ok_or(Error::BadRequest)?
            .to_string(),
    )
    .await?;

    Ok(HttpResponse::Ok().finish())
}
