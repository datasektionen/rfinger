use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, tempfile::TempFile};
use actix_web::http::header::{CacheControl, CacheDirective};
use actix_web::web::Redirect;
use actix_web::{App, get, middleware::Logger, web};
use actix_web::{HttpResponse, HttpServer, post};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use auth::auth_callback;
use auth::types::{AuthMiddleware, OIDCData};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use image::imageops::FilterType;
use image::{ImageFormat, ImageReader};
use openidconnect::http::response;
use std::io::{Cursor, Read};
use webp::{Encoder, WebPMemory};

mod auth;
mod error;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = aws_config::load_defaults(BehaviorVersion::latest())
        .await
        .into_builder()
        .endpoint_url("http://localhost:9090")
        .region(Region::new("us-west-2"))
        .build();

    let config = aws_sdk_s3::config::Builder::from(&config)
        .force_path_style(true)
        .build();
    let client = web::Data::new(aws_sdk_s3::Client::from_conf(config));
    let (oidc, auth_url) = OIDCData::get_oidc().await;
    let oidc = web::Data::new(oidc);
    let auth_url = auth_url.clone();

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(AuthMiddleware::new(auth_url.clone()))
            .app_data(client.clone())
            .app_data(oidc.clone())
            .service(index)
            .service(change_image)
            .service(get_me)
            .service(auth_callback)
            .service(get_image)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    image: TempFile,
}

#[get("/")]
async fn index() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("index.html")?)
}

#[post("/")]
async fn change_image(
    s3: web::Data<Client>,
    id: web::ReqData<String>,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Redirect {
    let image_bytes: Vec<u8> = form
        .image
        .file
        .as_file()
        .bytes()
        .map(|x| x.unwrap())
        .collect();

    let mime_type = form.image.content_type.unwrap().to_string();

    let img_format = ImageFormat::from_mime_type(&mime_type).unwrap();

    let image = ImageReader::with_format(Cursor::new(image_bytes), img_format)
        .decode()
        .unwrap();
    let image = image.resize(720, 720, FilterType::Lanczos3);

    // Make webp::Encoder from DynamicImage.
    let encoder: Encoder = Encoder::from_image(&image).unwrap();

    // Encode image into WebPMemory.
    let encoded_webp: WebPMemory = encoder.encode(65f32);

    let image_bytes: Vec<u8> = encoded_webp.bytes().map(|x| x.unwrap()).collect();

    s3.put_object()
        .bucket("rfinger")
        .key(id.as_str())
        .body(ByteStream::from(image_bytes))
        .content_type("image/webp")
        .send()
        .await
        .unwrap();

    Redirect::to("/").see_other()
}

#[get("/me")]
async fn get_me(s3: web::Data<Client>, id: web::ReqData<String>) -> HttpResponse {
    let response = s3
        .get_object()
        .bucket("rfinger")
        .key(id.as_str())
        .send()
        .await
        .unwrap();
    let data = response.body.collect().await.unwrap();
    let mime_type = response.content_type.unwrap();
    let bytes = data.into_bytes();

    HttpResponse::Ok().content_type(mime_type).body(bytes)
}

#[get("/{file}")]
async fn get_image(
    s3: web::Data<Client>,
    path: web::Path<String>,
) -> HttpResponse {
    let expires_in: std::time::Duration = std::time::Duration::from_secs(3600 * 36);
    let expires_in: aws_sdk_s3::presigning::PresigningConfig =
        PresigningConfig::expires_in(expires_in).unwrap();

    let presigned_request = s3
        .put_object()
        .bucket("rfinger")
        .key(path.as_str())
        .presigned(expires_in)
        .await
        .unwrap();

    let url = presigned_request.uri().to_string();

    HttpResponse::Ok()
        .insert_header(CacheControl(vec![CacheDirective::MaxAge(3600 * 24)]))
        .body(url)
}
