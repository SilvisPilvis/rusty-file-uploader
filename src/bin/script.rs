use sqlx::postgres::PgPoolOptions;
use std::env;
use std::io;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;
    dotenvy::dotenv()?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&env::var("DATABASE_URL")?)
        .await?;

    let actions = vec![
        "Create new user",
        "Scan Dir & Add files",
        "Reset password",
        "Create store",
        "Delete user",
        "Exit",
    ];

    println!("Choose your action: ");
    for (i, action) in actions.iter().enumerate() {
        println!("{}] {}", i + 1, action);
    }

    // Get user input
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    match input.trim().parse::<usize>() {
        Ok(action) => {
            match action {
                1 => {
                    // Create new user
                    println!("Enter username: ");
                }
                2 => {
                    // Scan Dir & Add files
                    println!("Enter directory path: ");
                }
                3 => {
                    // Reset password
                    println!("Enter username: ");
                }
                4 => {
                    // Create store
                    println!("Enter store name: ");
                }
                5 => {
                    // Delete user
                    println!("Enter username: ");
                }
                6 => {
                    // Exit
                    println!("Exiting...");
                    return Ok(());
                }
                _ => {
                    println!("Invalid input");
                }
            }
        }
        Err(_) => {
            println!("Invalid input");
        }
    }

    Ok(())
}
