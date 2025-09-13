use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile};
use actix_web::{
    App, HttpResponse, HttpServer, get,
    middleware::Logger,
    mime::Mime,
    post,
    web::{self, Redirect},
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use auth::types::{AuthMiddleware, OIDCData};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
use aws_sdk_s3::operation::put_object::{PutObjectError, PutObjectOutput};
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_runtime_api::http::Response;
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader};
use serde::Deserialize;
use std::{env, fmt::Display};
use std::{
    io::{Cursor, Read},
    str::FromStr,
};
use utoipa::{IntoParams, OpenApi};
use utoipa_actix_web::AppExt;
use utoipa_actix_web::service_config::ServiceConfig;
use utoipa_redoc::{Redoc, Servable};
use webp::{Encoder, WebPMemory};

use crate::auth::check_token;

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
                let first = chars.next().unwrap();
                let second = chars.next().unwrap();
                write!(f, "compressed_images/{first}/{second}/{kthid}")
            }
            PathType::Personal(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().unwrap();
                let second = chars.next().unwrap();
                write!(f, "personal_images/{first}/{second}/{kthid}")
            }
            PathType::Original(kthid) => {
                let mut chars = kthid.chars();
                let first = chars.next().unwrap();
                let second = chars.next().unwrap();
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
    async fn get_image(
        &self,
        kthid: &str,
        quality: bool,
    ) -> Result<GetObjectOutput, SdkError<GetObjectError, Response>> {
        let mut key;

        if !quality {
            key = PathType::Compressed(kthid.to_string());

            if let Ok(image) = self.get_object(&key.to_string()).await {
                return Ok(image);
            }
        }

        key = PathType::Personal(kthid.to_string());

        if let Ok(image) = self.get_object(&key.to_string()).await {
            return Ok(image);
        }

        key = PathType::Original(kthid.to_string());

        if let Ok(image) = self.get_object(&key.to_string()).await {
            return Ok(image);
        }

        key = PathType::Missing;

        self.get_object(&key.to_string()).await
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
        kthid: String,
        image: TempFile,
    ) -> Result<PutObjectOutput, SdkError<PutObjectError, Response>> {
        let image_bytes = get_bytes(&image);

        if let Err(error) = self
            .s3_client
            .put_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(path.to_string())
            .body(ByteStream::from(image_bytes.clone()))
            .content_type(
                image
                    .content_type
                    .clone()
                    .unwrap_or(Mime::from_str("image/jpeg").unwrap())
                    .to_string(),
            )
            .send()
            .await
        {
            return Err(error);
        }

        let image_bytes = process_image(image_bytes, image);

        self.s3_client
            .put_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(PathType::Compressed(kthid).to_string())
            .body(ByteStream::from(image_bytes))
            .content_type("image/webp")
            .send()
            .await
    }
}

fn get_bytes(image: &TempFile) -> Vec<u8> {
    image.file.as_file().bytes().map(|x| x.unwrap()).collect()
}

fn process_image(image_bytes: Vec<u8>, image: TempFile) -> Vec<u8> {
    let mime_type = image.content_type.unwrap().to_string();

    let img_format = ImageFormat::from_mime_type(&mime_type).unwrap();

    let image = ImageReader::with_format(Cursor::new(image_bytes), img_format)
        .decode()
        .unwrap();

    let image = image.resize(480, 480, FilterType::Lanczos3);

    // Make webp::Encoder from DynamicImage.
    let encoder: Encoder = Encoder::from_image(&image).unwrap();

    // Encode image into WebPMemory.
    let encoded_webp: WebPMemory = encoder.encode(65f32);

    encoded_webp.bytes().map(|x| x.unwrap()).collect()
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
) -> Redirect {
    if s3
        .put_image(
            PathType::Personal(kthid.to_string()),
            kthid.to_string(),
            form.image,
        )
        .await
        .is_ok()
    {
        Redirect::to("/").see_other()
    } else {
        Redirect::to("/").see_other()
    }
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

    let response = if let Ok(res) = response {
        res
    } else {
        return HttpResponse::InternalServerError().finish();
    };

    let data = response.body.collect().await.unwrap();
    let mime_type = response.content_type.unwrap();
    let bytes = data.into_bytes();

    HttpResponse::Ok().content_type(mime_type).body(bytes)
}

#[utoipa::path(tag = "api")]
#[get("/{kthid}")]
async fn get(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    query: web::Query<GetQuery>,
    auth: BearerAuth,
) -> HttpResponse {
    match check_token(auth.token(), "get").await {
        Ok(false) => return HttpResponse::Unauthorized().finish(),
        Ok(true) => {}
        Err(error) => {
            log::error!("failed to check token: {error}");
            return HttpResponse::InternalServerError().finish();
        }
    }

    let response = s3
        .get_image(&kthid.to_string(), query.quality.unwrap_or(false))
        .await;

    let response = match response {
        Ok(res) => res,
        Err(error) => {
            log::error!(
                "failed to get image {kthid}: {}",
                DisplayErrorContext(error)
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let data = response.body.collect().await.unwrap();
    let mime_type = response.content_type.unwrap();
    let bytes = data.into_bytes();

    HttpResponse::Ok().content_type(mime_type).body(bytes)
}

#[utoipa::path(tag = "api")]
#[post("/{kthid}")]
async fn upload(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    auth: BearerAuth,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> HttpResponse {
    match check_token(auth.token(), "upload").await {
        Ok(false) => return HttpResponse::Unauthorized().finish(),
        Ok(true) => {}
        Err(_) => return HttpResponse::InternalServerError().finish(),
    }

    if s3
        .put_image(
            PathType::Personal(kthid.to_string()),
            kthid.to_string(),
            form.image,
        )
        .await
        .is_ok()
    {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

#[utoipa::path(tag = "api")]
#[post("/nollan/{kthid}")]
async fn nollan(
    s3: web::Data<Client>,
    kthid: web::Path<String>,
    auth: BearerAuth,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> HttpResponse {
    match check_token(auth.token(), "nollan").await {
        Ok(false) => return HttpResponse::Unauthorized().finish(),
        Ok(true) => {}
        Err(_) => return HttpResponse::InternalServerError().finish(),
    }

    if s3
        .put_image(
            PathType::Original(kthid.to_string()),
            kthid.to_string(),
            form.image,
        )
        .await
        .is_ok()
    {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::InternalServerError().finish()
    }
}
