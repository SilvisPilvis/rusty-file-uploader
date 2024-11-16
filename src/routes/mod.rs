use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Extension, Multipart, Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chksum_hash_md5 as md5;
use jsonwebtoken::{self, encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use time::PrimitiveDateTime;
use tokio::{fs::File, io::AsyncReadExt, io::AsyncWriteExt};
use uuid::Uuid;

use crate::messages;
// use crate::middleware;
pub use crate::middleware::Claims;

#[derive(Deserialize, Serialize, Clone, Debug, sqlx::FromRow)]
pub struct User {
    // id: i32,
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, sqlx::FromRow)]
pub struct ResetPassword {
    username: String,
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CreateStore {
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct UpdateStore {
    name: String,
    cover: i32,
}

#[derive(Serialize)]
struct StoreFiles {
    file_ids: Vec<i32>,
}

#[derive(serde::Serialize)]
#[serde_with::serde_as]
struct UserStore {
    id: i32,
    name: String,
    // created_at: NaiveDateTime,
    #[serde_as(as = "TimestampMilliSeconds")]
    created_at: PrimitiveDateTime,
    cover: i32,
    file_count: i64,
}

#[derive(serde::Serialize)]
struct UserStores {
    user_stores: Vec<UserStore>,
}

struct Page {
    page: i64,
}

#[axum::debug_handler]
pub async fn health_check(
    _req: axum::http::Request<axum::body::Body>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    Ok((
        StatusCode::OK,
        messages::create_json_response(
            messages::MessageType::Message,
            "API is working".to_string(),
        ),
    ))
}

pub async fn register_user(
    State(pool): State<PgPool>,
    Json(user): Json<User>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if user.username == "" || user.password == "" {
        return Err((
            StatusCode::BAD_REQUEST,
            messages::create_json_response(
                messages::MessageType::Error,
                "Username or Password empty".to_string(),
            ),
        ));
    }

    let secert: String = env::var("SECRET").map_err(|_e| {
        ((
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to get SECRET from env".to_string(),
            ),
        ))
    })?;

    let password = user.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| {
            ((
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(messages::MessageType::Error, e.to_string()),
            ))
        })?
        .to_string();

    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
        user.username,
        password_hash
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(messages::MessageType::Error, e.to_string()),
        )
    })
    .map(|record| record.id);

    let inserted_id = match result {
        Ok(record) => record,
        Err(e) => return Err(e),
    };

    tracing::info!("New user id is: {inserted_id}");

    let message = format!("User: {} registered!", user.username.clone());
    tracing::info!("{message}");

    let claims = Claims {
        id: inserted_id,
        username: user.username,
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secert.as_ref()),
    ) {
        Ok(tok) => tok,
        Err(e) => {
            tracing::error!("Error generating token {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "Error generatin token".to_string(),
                ),
            ));
        }
    };

    // return Ok((StatusCode::OK, token));
    return Ok((
        StatusCode::OK,
        messages::create_json_response(messages::MessageType::Token, token),
    ));
}

pub async fn get_file_hash(file_path: &str) -> tokio::io::Result<String> {
    let mut file = File::open(file_path).await?;
    let mut hasher = md5::new();
    let mut buffer = [0; 1024];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result.digest()))
}

pub async fn login_user(
    State(pool): State<PgPool>,
    Json(credentials): Json<User>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let user = sqlx::query!(
        "SELECT id, password FROM users WHERE username = $1",
        credentials.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            // messages::create_json_response(messages::MessageType::Error, "User not found".to_string()),
            messages::create_json_response(messages::MessageType::Error, e.to_string()),
        )
    })?;

    let secert: String = env::var("SECRET").map_err(|_e| {
        ((
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to get SECRET from env".to_string(),
            ),
        ))
    })?;

    let user = user.ok_or((
        StatusCode::UNAUTHORIZED,
        messages::create_json_response(messages::MessageType::Error, "User not found".to_string()),
    ))?;
    let password = user.password.unwrap();
    let id = user.id;

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&password).map_err(|e| {
        ((
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(messages::MessageType::Error, e.to_string()),
        ))
    })?;

    if argon2
        .verify_password(credentials.password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        let claims = Claims {
            id: id,
            username: credentials.username.clone(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let token = match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secert.as_ref()),
        ) {
            Ok(tok) => tok,
            Err(e) => {
                tracing::error!("Error generating token {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    messages::create_json_response(
                        messages::MessageType::Error,
                        "Error generating token".to_string(),
                    ),
                ));
            }
        };

        let message = format!("User {} logged in.", credentials.username);
        tracing::info!("{message}");
        return Ok((
            StatusCode::OK,
            messages::create_json_response(messages::MessageType::Token, token),
        ));
    }

    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        messages::create_json_response(
            messages::MessageType::Error,
            "Error logging in".to_string(),
        ),
    ))
}

pub async fn upload_file(
    State(pool): State<PgPool>,
    Path(store_id): Path<i32>,
    mut multipart: Multipart,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if store_id <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            messages::create_json_response(
                messages::MessageType::Error,
                "Store id can't be equal to or less than zero".to_string(),
            ),
        ));
    }
    // Process file upload
    if let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            messages::create_json_response(
                messages::MessageType::Error,
                format!("Failed to process file upload: {}", e.to_string()).to_string(),
            ),
        )
    })? {
        let file_name = field
            .file_name()
            .ok_or((
                StatusCode::BAD_REQUEST,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "No filename provided".to_string(),
                ),
            ))?
            .to_string();

        // let content_type = field.content_type()
        //     .ok_or((StatusCode::BAD_REQUEST, "No content type provided".to_string()))?
        //     .to_string();

        // Generate unique filename
        let file_id = Uuid::new_v4();
        let extension = std::path::Path::new(&file_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("bin"); // if no extension then default to .bin
        let new_filename = format!("{}.{}", file_id, extension);
        let upload_path = format!("uploads/{}", new_filename);

        // Ensure uploads directory exists
        tokio::fs::create_dir_all("uploads").await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "Failed to create uploads directory".to_string(),
                ),
            )
        })?;

        // Save file
        let contents = field.bytes().await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "Failed to read uploaded file contents".to_string(),
                ),
            )
        })?;

        let mime_type = infer::get(&contents)
            .map_or("application/octet-stream", |kind| kind.mime_type())
            .to_string();

        let mut file = File::create(&upload_path).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "Failed to create file on disk".to_string(),
                ),
            )
        })?;

        file.write_all(&contents).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "Failed to write file to disk".to_string(),
                ),
            )
        })?;

        let uploaded_file_path = format!("./uploads/{}", &new_filename);

        let file_hash = match get_file_hash(uploaded_file_path.as_str()).await {
            Ok(hash) => hash,
            Err(e) => {
                tracing::error!("Error generating token {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    messages::create_json_response(
                        messages::MessageType::Error,
                        "Failed to generate token".to_string(),
                    ),
                ));
            }
        };

        let uploaded_file = sqlx::query!(
            // "INSERT INTO files (name, content_type, original_name, md5) VALUES ($1, $2, $3) RETURNING id",
            "INSERT INTO files (name, content_type, md5) VALUES ($1, $2, $3) RETURNING id",
            new_filename,
            // field.name,
            mime_type,
            file_hash,
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Error,
                    "Failed to save file in db".to_string(),
                ),
            )
        })
        .map(|record| record.id);

        let inserted_id = match uploaded_file {
            Ok(record) => record,
            Err(e) => return Err(e),
        };

        sqlx::query!(
            "INSERT INTO file_store (storeId, fileId) VALUES ($1, $2)",
            store_id,
            inserted_id
        )
        .execute(&pool)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(
                    messages::MessageType::Message,
                    "Failed to save add file to store".to_string(),
                ),
            )
        })?;

        // let message = format!("/files/{}", file_id);
        return Ok((
            StatusCode::OK,
            messages::create_json_response(
                messages::MessageType::Message,
                "Succesfully uploaded files".to_string(),
            ),
        ));

        // tracing::info!("{} uploaded {} files")
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            messages::create_json_response(
                messages::MessageType::Error,
                "No file provided".to_string(),
            ),
        ));
    };
}

pub async fn get_file_by_id(
    State(pool): State<PgPool>,
    // Path(file_id): Path<Uuid>,
    Path(file_id): Path<i32>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Get file metadata from database using ID
    let file_meta = sqlx::query!(
        // "SELECT name, content_type, path FROM files WHERE id = $1",
        "SELECT name, content_type FROM files WHERE id = $1",
        file_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(messages::MessageType::Error, e.to_string()),
        )
    })?
    .ok_or((
        StatusCode::NOT_FOUND,
        messages::create_json_response(messages::MessageType::Error, "File not found".to_string()),
    ))?;

    // 2. Read file contents
    let uploaded_file_path = format!("./uploads/{}", &file_meta.name.clone().unwrap());
    tracing::info!("trying to open file: {uploaded_file_path}");
    let mut file = File::open(&uploaded_file_path).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            messages::create_json_response(
                messages::MessageType::Error,
                "File not found".to_string(),
            ),
        )
    })?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to read file".to_string(),
            ),
        )
    })?;

    // 3. Return file with proper headers
    tracing::info!("show file in response");
    Ok((
        [
            (header::CONTENT_TYPE, file_meta.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", file_meta.name.unwrap()),
            ),
        ],
        contents,
    ))
}

pub async fn get_file_by_id_base64(
    State(pool): State<PgPool>,
    Path(file_id): Path<i32>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Get file metadata from database using ID
    let file_meta = sqlx::query!(
        "SELECT name, content_type FROM files WHERE id = $1",
        file_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(messages::MessageType::Error, e.to_string()),
        )
    })?
    .ok_or((
        StatusCode::NOT_FOUND,
        messages::create_json_response(messages::MessageType::Error, "File not found".to_string()),
    ))?;

    // 2. Read file contents and base64 encode
    let uploaded_file_path = format!("./uploads/{}", &file_meta.name.clone().unwrap());
    tracing::info!("trying to open file: {uploaded_file_path}");

    let mut file = File::open(&uploaded_file_path).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            messages::create_json_response(
                messages::MessageType::Error,
                "File not found".to_string(),
            ),
        )
    })?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to read file".to_string(),
            ),
        )
    })?;

    // 3. Base64 encode the file contents
    // let base64_contents = Engine::encode(self, &contents);
    let base64_contents = general_purpose::STANDARD.encode(&contents);
    // let base64_contents = base64::encode(&contents);

    // 4. Return a JSON response with base64 encoded file
    let response = serde_json::json!({
        "filename": file_meta.name.unwrap(),
        "content_type": file_meta.content_type,
        "base64_content": base64_contents
    });

    tracing::info!("Returning base64 encoded file");
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&response).unwrap(),
    ))
}

pub async fn get_files_from_store(
    State(pool): State<PgPool>,
    Path(store_id): Path<i32>,
    Json(page): Json<Page>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let file_ids = sqlx::query!(
        "SELECT fileId FROM file_store WHERE storeId = $1 LIMIT 20 OFFSET $2",
        store_id,
        page.page,
    )
    .fetch_all(&pool) // Changed from fetch_optional to fetch_all
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to get files from db".to_string(),
            ),
        )
    })?
    .into_iter()
    .map(|record| record.fileid)
    .collect::<Vec<i32>>();

    // Return JSON response
    Ok(Json(StoreFiles { file_ids }))
}

pub async fn get_user_stores(
    Extension(claims): Extension<Claims>,
    State(pool): State<PgPool>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user_stores = sqlx::query!(
        "SELECT
        s.id,
        s.name,
        s.cover,
        s.created_at,
        COUNT(fs.fileId) as file_count
        FROM stores s
        INNER JOIN user_store us ON s.id = us.storeId
        LEFT JOIN file_store fs ON fs.storeId = s.id
        WHERE us.userId = $1
        GROUP BY s.id, s.name, s.created_at, s.cover
        ORDER BY s.created_at DESC;",
        claims.id
    )
    .fetch_all(&pool) // Changed from fetch_optional to fetch_all
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to get files from db".to_string(),
            ),
        )
    })?
    .into_iter()
    .map(|record| UserStore {
        id: record.id,
        name: record.name.expect("Store has no name"),
        created_at: record.created_at,
        file_count: record.file_count.expect("No files in store"),
        cover: record
            .cover
            // .expect("No cover for store")
            .unwrap_or(0),
    })
    .collect::<Vec<UserStore>>();

    // Return JSON response
    Ok(Json(UserStores { user_stores }))

    // Or if you prefer to return just the array:
    // Ok(Json(file_ids))
}

pub async fn create_store(
    Extension(claims): Extension<Claims>,
    State(pool): State<PgPool>,
    Json(store): Json<CreateStore>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let file_store = sqlx::query!(
        "INSERT INTO stores (name) VALUES ($1) RETURNING id",
        store.name
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(messages::MessageType::Error, e.to_string()),
        )
    })
    .map(|record| record.id);
    // .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    let inserted_id = match file_store {
        Ok(record) => record,
        Err(e) => return Err(e),
    };

    sqlx::query!(
        "INSERT INTO user_store (storeId, userId) VALUES ($1, $2)",
        inserted_id,
        claims.id
    )
    .execute(&pool)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to save add file to store".to_string(),
            ),
        )
    })?;

    let message = format!(
        "store {} with id: {} created succesfully",
        store.name, inserted_id
    );
    return Ok((
        StatusCode::OK,
        messages::create_json_response(messages::MessageType::Message, message.to_string()),
    ));
}

pub async fn update_store(
    Extension(claims): Extension<Claims>,
    State(pool): State<PgPool>,
    Path(store_id): Path<i32>,
    Json(store): Json<UpdateStore>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    sqlx::query!(
        "UPDATE stores SET name = $1, cover = $2 WHERE id = $3",
        store.name,
        store.cover,
        store_id
    )
    .execute(&pool)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to update store".to_string(),
            ),
        )
    })?;

    let message = format!("store {} updated succesfully", store.name);
    return Ok((
        StatusCode::OK,
        messages::create_json_response(messages::MessageType::Message, message.to_string()),
    ));
}

pub async fn reset_password(
    State(pool): State<PgPool>,
    Json(user): Json<ResetPassword>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let password = user.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| {
            ((
                StatusCode::INTERNAL_SERVER_ERROR,
                messages::create_json_response(messages::MessageType::Error, e.to_string()),
            ))
        })?
        .to_string();

    sqlx::query!(
        "UPDATE users SET password = $1 WHERE username = $2",
        password_hash,
        user.username,
    )
    .execute(&pool)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            messages::create_json_response(
                messages::MessageType::Error,
                "Failed to update password".to_string(),
            ),
        )
    })?;

    let message = format!("Reset {}'s password succesfully", user.username);
    return Ok((
        StatusCode::OK,
        messages::create_json_response(messages::MessageType::Message, message.to_string()),
    ));
}

pub async fn migrate(pool: PgPool) -> Result<(), color_eyre::Report> {
    sqlx::migrate!("src/migrations/").run(&pool).await?;

    // return Ok((StatusCode::OK, messages::create_json_response(messages::MessageType::Message, message.to_string())))
    return Ok(());

    // sqlx::query_file!("src/migrations/20241015210239_create-tables.sql")
    // .execute(&pool)
    // .await
    // .map_err(|_| {
    //     (
    //         StatusCode::INTERNAL_SERVER_ERROR,
    //         messages::create_json_response(messages::MessageType::Error, "Failed to migrate database".to_string()),
    //     )
    // })?;
}
