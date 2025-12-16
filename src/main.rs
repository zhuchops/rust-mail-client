use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, command};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

mod client;

// clap structures

#[derive(Args)]
struct RegisterArgs {
    #[arg(short, long)]
    username: String,
    #[arg(short, long)]
    password: String,
}

#[derive(Args)]
struct LoginArgs {
    #[arg(short, long)]
    username: String,
    #[arg(short, long)]
    password: String,
}

#[derive(Subcommand)]
enum AuthSubcommands {
    Register(RegisterArgs),
    Login(LoginArgs),
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand)]
    Auth(AuthSubcommands),
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// reqwest structures

#[derive(Serialize, Deserialize, Debug)]
struct CreateUser {
    username: String,
    password: String,
}

struct User {
    id: i32,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Token {
    pub token: String,
}

// file system structures

#[derive(Serialize, Deserialize)]
struct AuthConfig {
    pub access_token: Option<String>,
}

impl AuthConfig {
    fn get_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("rust_mail");
        path.push("config.json");
        path
    }

    async fn save(&self) -> anyhow::Result<()> {
        let path = Self::get_path();

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let json = serde_json::to_string(self)?;
        tokio::fs::write(path, json).await?;

        Ok(())
    }

    async fn load() -> anyhow::Result<Self> {
        let path = Self::get_path();
        let content = tokio::fs::read_to_string(path).await?;
        let config: AuthConfig = serde_json::from_str(&content)?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = Client::new();
    let mut config = AuthConfig { access_token: None };

    match cli.command {
        Commands::Auth(auth_subcommands) => match auth_subcommands {
            AuthSubcommands::Register(args) => {
                println!(
                    "You chose to register with {} and {}",
                    args.username, args.password
                );
                let new_user = CreateUser {
                    username: args.username,
                    password: args.password,
                };
                let response = client
                    .post("http://localhost:3000/users/auth/register")
                    .json(&new_user)
                    .send()
                    .await?;

                match response.status() {
                    StatusCode::OK => {
                        let token: Token = response.json().await?;
                        config.access_token = Some(token.token.clone());
                        config.save().await?;
                        println!("Your token: {:?}", token);
                    }
                    StatusCode::CONFLICT => {
                        println!("Username is already taken. Try another one")
                    }
                    StatusCode::INTERNAL_SERVER_ERROR => {
                        println!("Internal server error. Try again")
                    }
                    _ => {}
                }
            }
            AuthSubcommands::Login(args) => {
                println!(
                    "You chose to login with {} and {}",
                    args.username, args.password
                );
                let new_user = CreateUser {
                    username: args.username,
                    password: args.password,
                };
                let response = client
                    .post("http://localhost:3000/users/auth/login")
                    .json(&new_user)
                    .send()
                    .await?;

                match response.status() {
                    StatusCode::OK => {
                        let token: Token = response.json().await?;
                        config.access_token = Some(token.token.clone());
                        config.save().await?;
                        println!("Your token: {:?}", token);
                    }
                    StatusCode::UNAUTHORIZED => {
                        println!("Username or password is invalid. Try again")
                    }
                    StatusCode::INTERNAL_SERVER_ERROR => {
                        println!("Internal server error. Try again")
                    }
                    _ => {}
                }
            }
        },
    }

    Ok(())
}
