use std::{
    collections::HashMap,
    env,
    fmt::Display,
    io::{Cursor, Read},
    sync::Mutex,
    time::{Duration, SystemTime},
};

use actix_multipart::form::tempfile::TempFile;
use actix_web::web::Bytes;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    error::SdkError,
    operation::{
        get_object::{GetObjectError, GetObjectOutput},
        put_object::{PutObjectError, PutObjectOutput},
    },
    presigning::{PresignedRequest, PresigningConfig},
    primitives::ByteStream,
    types::error::{InvalidObjectState, NoSuchKey},
};
use aws_smithy_runtime_api::http::Response;
use chrono::{DateTime, Utc};
use image::{ImageFormat, ImageReader, imageops::FilterType};
use reqwest::header::CONTENT_TYPE;
use webp::{Encoder, WebPMemory};

use crate::error::Error;

/// Paths to images in s3 bucket
///
/// Original: original_images/<k>/<t>/<kthid>
///     used for the nolle picture
///
/// Personal: personal_images/<k>/<t>/<kthid>
///     used for image uploaded by the person
///
/// Compressed: compressed_images/<k>/<t>/<kthid>
///     used for profile sized picture
///
/// Missing: missing.svg
///     used if no other picture is found
pub enum PathType {
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

/// A s3 bucket client with custom functions
pub struct Client {
    s3_client: aws_sdk_s3::Client,
    cache: Mutex<HashMap<String, LinkCache>>,
}

pub struct LinkCache {
    link: PresignedRequest,
    ttl: DateTime<Utc>,
}

impl Client {
    pub async fn new() -> Self {
        // aws_config needs to be modified to allow local development
        let config = aws_config::load_defaults(BehaviorVersion::latest())
            .await
            .into_builder()
            // .endpoint_url("http://localhost:9090")
            .region(Region::new("eu-west-1"))
            .build();

        // local s3 bucket emplators often only support path style queries
        let config = aws_sdk_s3::config::Builder::from(&config)
            // .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);

        Client {
            s3_client: client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get a picture from s3
    ///
    /// Priority: compressed > personal > original > missing
    ///
    /// if high quality was requested ignore compressed
    pub async fn get_image(&self, kthid: &str, quality: bool) -> Result<(Bytes, String), Error> {
        let mut key;

        // If profile picture requested try to get compressed
        if !quality {
            key = PathType::Compressed(kthid.to_string());

            if let Ok(image) = self.get_object(&key.to_string()).await {
                return Ok(Client::parse_get_object(image).await?);
            }
        }

        key = PathType::Personal(kthid.to_string());

        if let Some(url) = self.get_quality_image(kthid, key, quality).await? {
            return Ok(url);
        }

        key = PathType::Original(kthid.to_string());

        if let Some(url) = self.get_quality_image(kthid, key, quality).await? {
            return Ok(url);
        }

        key = PathType::Missing;

        // If no picture was found, return default
        let image = self.get_object(&key.to_string()).await?;
        let (image_bytes, mime_type) = Client::parse_get_object(image).await?;
        Ok((image_bytes, mime_type))
    }

    async fn get_quality_image(
        &self,
        kthid: &str,
        key: PathType,
        quality: bool,
    ) -> Result<Option<(Bytes, String)>, Error> {
        if let Ok(image) = self.get_object(&key.to_string()).await {
            let (image_bytes, mime_type) = Client::parse_get_object(image).await?;

            // If profile sized picture was requested but not found, create it
            if !quality {
                let compressed = process_image(image_bytes.to_vec(), &mime_type)?;
                self.put_object(
                    PathType::Compressed(kthid.to_string()),
                    compressed.clone(),
                    "image/webp",
                )
                .await?;

                return Ok(Some((Bytes::from(compressed), mime_type)));
            } else {
                return Ok(Some((image_bytes, mime_type)));
            }
        } else {
            Ok(None)
        }
    }

    async fn parse_get_object(image: GetObjectOutput) -> Result<(Bytes, String), Error> {
        let image_bytes = image.body.collect().await?.into_bytes();
        let mime_type = image
            .content_type
            .clone()
            .ok_or(Error::InternalServerError(String::from(
                "image has no mime type",
            )))?;

        Ok((image_bytes, mime_type))
    }

    /// Helper function to make getting things from s3 easier
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

    /// Get a prisigned url to an image from s3
    ///
    /// Priority: compressed > personal > original > missing
    ///
    /// if high quality was requested ignore compressed
    pub async fn get_presigned_image(&self, kthid: &str, quality: bool) -> Result<String, Error> {
        let mut key;

        // If profile picture requested try to get compressed
        if !quality {
            key = PathType::Compressed(kthid.to_string());

            if let Ok(presigned) = self.get_presigned(&key.to_string()).await {
                return Ok(presigned.uri().to_string());
            }
        }

        key = PathType::Personal(kthid.to_string());

        if let Some(url) = self.get_quality_presigned(kthid, key, quality).await? {
            return Ok(url);
        }

        key = PathType::Original(kthid.to_string());

        if let Some(url) = self.get_quality_presigned(kthid, key, quality).await? {
            return Ok(url);
        }

        key = PathType::Missing;

        // If no picture was found, return default
        Ok(self
            .get_presigned(&key.to_string())
            .await?
            .uri()
            .to_string())
    }

    /// Helper function for getting things from s3 easier
    async fn get_quality_presigned(
        &self,
        key: &str,
        path: PathType,
        quality: bool,
    ) -> Result<Option<String>, Error> {
        if let Ok(presigned) = self.get_presigned(&path.to_string()).await {
            // If profile sized picture was requested but not found, create it
            if !quality {
                let res = reqwest::get(presigned.uri()).await?;
                let mime_type = res
                    .headers()
                    .get(CONTENT_TYPE)
                    .ok_or(Error::InternalServerError(String::from(
                        "no mime_type in s3",
                    )))?
                    .to_str()?
                    .to_string();
                let image_bytes = res.bytes().await?;
                let compressed = process_image(image_bytes.to_vec(), &mime_type)?;
                self.put_object(
                    PathType::Compressed(key.to_string()),
                    compressed.clone(),
                    "image/webp",
                )
                .await?;

                return Ok(Some(
                    self.get_presigned(&PathType::Compressed(key.to_string()).to_string())
                        .await?
                        .uri()
                        .to_string(),
                ));
            } else {
                return Ok(Some(presigned.uri().to_string()));
            }
        } else {
            Ok(None)
        }
    }

    async fn get_presigned(
        &self,
        key: &str,
    ) -> Result<PresignedRequest, SdkError<GetObjectError, Response>> {
        if let Ok(lock) = self.cache.lock()
            && let Some(cache) = lock.get(key)
            && cache.ttl > chrono::offset::Local::now()
        {
            return Ok(cache.link.clone());
        }
        if let Err(err) = self
            .s3_client
            .head_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(key.to_string())
            .send()
            .await
        {
            return Err(
                err.map_service_error(|_| GetObjectError::NoSuchKey(NoSuchKey::builder().build()))
            );
        }

        let config = PresigningConfig::expires_in(Duration::from_secs(12 * 3600)).unwrap();

        let link = self
            .s3_client
            .get_object()
            .bucket(env::var("S3_BUCKET").expect("bucket name env"))
            .key(key.to_string())
            .presigned(config)
            .await?;

        if let Ok(mut lock) = self.cache.lock() {
            lock.insert(
                key.to_string(),
                LinkCache {
                    link: link.clone(),
                    ttl: chrono::offset::Utc::now() + Duration::from_secs(8 * 3600),
                },
            );
        }

        Ok(link)
    }

    /// Upload an image to s3
    ///
    /// Upload it to the specified place and upload a compressed version
    pub async fn put_image(
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

    /// Helper function to make putting things in s3 easier
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

/// Extract the image bytes from a temp file
pub fn get_bytes(image: &TempFile) -> Result<Vec<u8>, std::io::Error> {
    image
        .file
        .as_file()
        .bytes()
        .map(|x| x)
        .collect::<Result<Vec<u8>, std::io::Error>>()
}

/// Convert any image to a 480x480 webp encoded image
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
