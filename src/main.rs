use color_eyre;
use axum::{
    extract::{Path, State}, http::{HeaderMap, StatusCode}, routing::{get, post}, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
// use serde_json;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use jsonwebtoken::{self, decode, encode, DecodingKey, EncodingKey, Header, Validation};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;


#[derive(Deserialize, Serialize, Clone, Debug)]
struct User {
    id: i32,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    id: i32,
    username: String,
    exp: usize,
}

// Custom error type
enum CustomError {
    NotFound,
    InternalServerError,
    Ok
}

// Implement IntoResponse for CustomError
// impl IntoResponse for CustomError {
//     fn into_response(self) -> Response {
//         let (status, error_message) = match self {
//             CustomError::NotFound => (StatusCode::NOT_FOUND, "Not Found"),
//             CustomError::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
//         };
//         (status, error_message).into_response()
//     }
// }

#[axum::debug_handler]
async fn health_check(_req: axum::http::Request<axum::body::Body>,) -> Result<(StatusCode, String), (StatusCode, String)> {
    // let res = Response::builder()
    //     .status(StatusCode::OK)
    //     .body("API Is Up".to_string())
    //     .unwrap()?;
    // return res;
    // return Ok("API Is Up".to_string());
    Ok((StatusCode::OK, "Success!".to_string()))
}

async fn register_user(State(pool): State<PgPool>, Json(user): Json<User>) -> Result<(StatusCode, String), (StatusCode, String)> {
    if user.username == "" && user.password == "" {
        return Err((StatusCode::BAD_REQUEST, "Username or Password empty".to_string()));
    }

    let password = user.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &salt).map_err(|e| ((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())))?.to_string();

    sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        user.username,
        password_hash
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e.to_string())));

    let message = format!("User: {} registered!", user.username.clone());
    tracing::info!("{message}");

    let claims = Claims {
        id: 0,
        username: user.username,
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
    };

    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret("use-stringfrom-dot-env-here".as_ref())) {
        Ok(tok) => tok,
        Err(e) => {
            tracing::error!("Error generating token {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Error generating token".to_string()));
        }
    };

    return Ok((StatusCode::OK, token));
}

async fn login_user(State(pool): State<PgPool>, Json(user): Json<User>) -> Result<(StatusCode, String), (StatusCode, String)> {
    let db_user = sqlx::query_as!(
        User,
        "SELECT password, id FROM users WHERE username = $1;",
        user.username
    )
    .fetch_one(&pool)
    // .fetch_all(&pool)
    // .fetch(&pool);
    .await
    .map_err(|_e| (StatusCode::INTERNAL_SERVER_ERROR, "Database error: User Not Found".to_string()));

    // let db_password: String = row?.password.unwrap();
    // let db_id = row?.id as u64;
    // let (db_password, db_id) = (db_user?.password, db_user.unwrap().id);
    // let  = db_user.unwrap().id as u64;

    if db_user?.username == "" || db_user?.password == "null" {
        return Err((StatusCode::BAD_REQUEST, "User is not registered".to_string()))
    }

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&db_user?.password).map_err(|e| ((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())))?;

    if argon2.verify_password(user.password.as_bytes(), &parsed_hash).is_ok() {
        let claims = Claims {
            id: db_user?.id,
            username: user.username.clone(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize
        };

        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret("use-stringfrom-dot-env-here".as_ref())) {
            Ok(tok) => tok,
            Err(e) => {
                tracing::error!("Error generating token {}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Error generating token".to_string()));
            }
        };
    
        let message = format!("User {} logged in.", user.username);
        // let message = "User logged in.".to_string();
        tracing::info!("{message}");
        return Ok((StatusCode::OK, token));
    }

    Err((StatusCode::INTERNAL_SERVER_ERROR, "Error loging in".to_string()))
}

// #[derive(Clone)]
// struct TempDirState {
//     tempdir: Arc<TempDir>,
// }

// impl TempDirState {
//     fn try_new() -> Result<Self, color_eyre::Report>{
//         Ok(Self {
//             tempdir: Arc::new(tempfile::tempdir()?),
//         })
//     }

//     fn path(&self) -> &Path {
//         self.tempdir.path()
//     }
// }

async fn upload_file(headers: HeaderMap) -> Result<(StatusCode, String), (StatusCode, String)> {
    let mut token: String = "".to_string();
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_header_str) = auth_header.to_str() {
            if auth_header_str.starts_with("Bearer") {
                token = auth_header_str.trim_start_matches("Bearer ").to_string();
                // tracing::info!("Token: {}", token);
                match decode::<Claims>(&token, &DecodingKey::from_secret("use-stringfrom-dot-env-here".as_ref()), &Validation::default()) {
                    Ok(_) => {
                        return Ok((StatusCode::OK, "return this if user logged in".to_string()));
                    },
                    Err(e) => {
                        tracing::error!("Error generating token {}", e);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                    }
                }
            }
        }
    }

    // let mut body = req.body_bytes().await?;
    

    // let test = tide::Body::from_file(file!()).await?;
    // let pool = req.state();
    // sqlx::query!(
    //     "INSERT INTO users (username, password) VALUES ($1, $2)",
    //     user.username,
    //     user.password
    // )
    // .execute(pool)
    // .await?;
    // let form = req.body_form().await?;
    // res.set_body(format!("User: {} uploaded {} files!", user.username.clone(), file_count));

    return Ok((StatusCode::OK, format!("request token: {}", token)));
}



#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:postgres@localhost/postgres").await?;

    tracing::info!("Connected to database");

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    
    let app = Router::new()
        .route("/", get(health_check))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/upload", post(upload_file))
        .with_state(pool)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new()
                    .level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new()
                    .level(Level::INFO)),
        );
    
    // app.with(tide::log::LogMiddleware::new());

    // app.at("/").get(health_check);
    // app.at("/register").post(register_user);
    // app.at("/login").post(login_user);
    // app.at("/upload").put(upload_file);

    // app.listen("127.0.0.1:8000").await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    // log::info!("Write Uploaded files to tempdir and if upload fails drop tempdir to delete files and try again");
    // log::info!("Or maybe just write file to upload dir and of chunk not whole then delete last chunk");
    // log::info!("Frontend loadingbar chunk number as progress");

    Ok(())
}
