use color_eyre::eyre::Result;
use femme;
use tide;
use tide::log as log;
use sqlx::PgPool;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
struct User {
    username: String,
    password: String,
}

// async fn health_check(_req: tide::Request<()>) -> tide::Result<String> {
//     Ok("API is healthy".to_string())
// }

async fn health_check(_req: tide::Request<PgPool>) -> tide::Result<String> {
    Ok("API is healthy".to_string())
}

async fn register_user(mut req: tide::Request<PgPool>) -> tide::Result<String> {
    let user: User = req.body_json().await?;
    let pool = req.state();
    sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        user.username,
        user.password
    )
    .execute(pool)
    .await?;
    Ok(format!("User: {} registered!", user.username.clone()))
}

#[tokio::main]
async fn main() -> Result<()> {
    femme::with_level(femme::LevelFilter::Info);

    color_eyre::install()?;

    std::env::set_var("DATABASE_URL", "postgresql://postgres:SanaS*7Brec@vinetaerentraute.id.lv/database");

    let database_url = std::env::var("DATABASE_URL")
    .expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url).await?;

    log::info!("Connected to database");

    let mut app = tide::with_state(pool);
    // let mut app = tide::new();
    
    app.with(
        tide::log::LogMiddleware::new()
    );

    app.at("/").get(health_check);
    app.at("/register").post(register_user);

    app.listen("127.0.0.1:8000").await?;


    Ok(())
}
