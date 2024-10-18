use color_eyre;
use femme;
use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router,
};
use serde::{Deserialize, Serialize};
// use tide::log as log;
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
use hmac::{Hmac, Mac};
use sha2::Sha384;
use jwt::{AlgorithmType, Header, SignWithKey, Token};
use std::collections::BTreeMap;
use tempfile::TempDir;
use std::sync::Arc;
use std::path::Path;

#[derive(Deserialize, Serialize, Clone, Debug)]
struct User {
    username: String,
    password: String,
}

async fn health_check() -> Result {
    // let mut res = Response::new(200);
    // res.set_body("API Is Up");
    // Ok(res)
}

async fn register_user(mut req: tide::Request<PgPool>) -> tide::Result {
    let user: User = req.body_json().await?;
    let pool = req.state();
    let password = user.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &salt).map_err(|e| anyhow::anyhow!(e))?.to_string();

    sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        user.username,
        password_hash
    )
    .execute(pool)
    .await?;

    let message = format!("User: {} registered!", user.username.clone());
    log::info!("{message}");

    // let claims = serde_json::json!({
    //     "username": user.username,
    //     "exp": None, // token doesn't expire
    // });
    let token_key: Hmac<Sha384> = Hmac::new_from_slice(b"use-stringfrom-dot-env-here")?;
    let header = Header {
        algorithm: AlgorithmType::Hs384,
        ..Default::default()
    };
    let mut claims = BTreeMap::new();
    claims.insert("username", user.username);
    claims.insert("exp", "".to_string());

    let token = Token::new(header, claims).sign_with_key(&token_key)?;

    let mut res = tide::Response::new(200);
    res.set_body("Login successful");
    res.append_header("Authorization", format!("Bearer {}", token.as_str()));

    return Ok(res);
}

async fn login_user(mut req: tide::Request<PgPool>) -> tide::Result {
    let user: User = req.body_json().await?;
    let pool = req.state();

    let row = sqlx::query!(
        "SELECT password FROM users WHERE username = $1;",
        user.username
    )
    .fetch_one(pool)
    .await?;

    let db_password: String= row.password.unwrap();
    let message = format!("Password is: {db_password}");
    log::info!("{message}");
    if db_password == "" || db_password == "null" {
        let mut res = tide::Response::new(400);
        res.set_body("User is not registered");
        return Ok(res)
    }

    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(&db_password).map_err(|e| anyhow::anyhow!(e))?;

    if argon2.verify_password(user.password.as_bytes(), &parsed_hash).is_ok() {
        let token_key: Hmac<Sha384> = Hmac::new_from_slice(b"use-stringfrom-dot-env-here")?;
        let header = Header {
            algorithm: AlgorithmType::Hs384,
            ..Default::default()
        };
        let mut claims = BTreeMap::new();
        claims.insert("username", user.username);
        claims.insert("exp", "".to_string());
    
        let token = Token::new(header, claims).sign_with_key(&token_key)?;

        let mut res = tide::Response::new(200);
        res.set_body("Login successful");
        res.append_header("Authorization", format!("Bearer {}", token.as_str()));

        return Ok(res);
    }
    let mut res = tide::Response::new(400);
    res.set_body("Invalid Username or Password");
    Ok(res)
}

#[derive(Clone)]
struct TempDirState {
    tempdir: Arc<TempDir>,
}

impl TempDirState {
    fn try_new() -> Result<Self, color_eyre::Report>{
        Ok(Self {
            tempdir: Arc::new(tempfile::tempdir()?),
        })
    }

    fn path(&self) -> &Path {
        self.tempdir.path()
    }
}

async fn upload_file(req: tide::Request<PgPool>) -> tide::Result {
    // let mut body = req.body_bytes().await?;
    let token = req.header("Authorization").ok_or("");

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

    let mut res = tide::Response::new(200);
    // res.set_body(format!("User: {} uploaded {} files!", user.username.clone(), file_count));
    res.set_body(format!("Token: {:?}", token));
    return Ok(res);
}



#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    femme::with_level(femme::LevelFilter::Info);
    color_eyre::install()?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://postgres:postgres@localhost/postgres").await?;

    log::info!("Connected to database");

    let app = Router::new()
        .route("/", get(health_check))
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/upload", .post(upload_file));
    
    // app.with(tide::log::LogMiddleware::new());

    // app.at("/").get(health_check);
    // app.at("/register").post(register_user);
    // app.at("/login").post(login_user);
    // app.at("/upload").put(upload_file);

    // app.listen("127.0.0.1:8000").await?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    log::info!("Write Uploaded files to tempdir and if upload fails drop tempdir to delete files and try again");
    log::info!("Or maybe just write file to upload dir and of chunk not whole then delete last chunk");
    log::info!("Frontend loadingbag chunk  number as progress");

    Ok(())
}
