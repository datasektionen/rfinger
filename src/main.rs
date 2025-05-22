use actix_cors::Cors;
use actix_files::NamedFile;
use actix_multipart::form::{MultipartForm, json::Json as MpJson, tempfile::TempFile};
use actix_web::{App, get, middleware::Logger, web};
use actix_web::{HttpResponse, HttpServer, post};
use auth::auth_callback;
use auth::types::{AuthMiddleware, OIDCClient, OIDCData};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use serde::Deserialize;
use std::io::Read;
use std::path;

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
) -> HttpResponse {
    let image_bytes: Vec<u8> = form
        .image
        .file
        .as_file()
        .bytes()
        .map(|x| x.unwrap())
        .collect();

    let mime_type = form.image.content_type.unwrap().to_string();

    s3.put_object()
        .bucket("rfinger")
        .key(id.as_str())
        .body(ByteStream::from(image_bytes))
        .content_type(mime_type)
        .send()
        .await
        .unwrap();

    HttpResponse::Ok().finish()
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
async fn get_image(s3: web::Data<Client>, path: web::Path<String>) -> HttpResponse {
    let expires_in: std::time::Duration = std::time::Duration::from_secs(3600 * 24);
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

    HttpResponse::Ok().body(url)
}
