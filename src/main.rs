use std::{error, path::PathBuf};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, command};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::fs;

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

#[derive(Args)]
struct SendArgs {
    #[arg(short, long)]
    receiver: String,
    #[arg(short, long)]
    theme: String,
    #[command(flatten)]
    content: MailMessageVariants,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct MailMessageVariants {
    #[arg(short, long)]
    message: Option<String>,
    #[arg(short, long)]
    file: Option<PathBuf>,
}

#[derive(Args)]
#[group(required = false, multiple = false)]
struct ListArgs {
    // #[arg(short, long)]
    // read: bool,
    // #[arg(short, long)]
    // unread: bool,
    // #[arg(short, long)]
    // sent: bool,
}

#[derive(Args)]
struct OpenArgs {
    #[arg(short, long)]
    index: i32,
}

#[derive(Subcommand)]
enum AuthSubcommands {
    Register(RegisterArgs),
    Login(LoginArgs),
}

#[derive(Subcommand)]
enum MailSubcommands {
    Send(SendArgs),
    List(ListArgs),
    Open(OpenArgs),
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand)]
    Auth(AuthSubcommands),
    #[command(subcommand)]
    Mail(MailSubcommands),
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
struct Mail {
    id: i32,
    theme: String,
    text: String,
    status: String,
    sender: String,
    receiver: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Token {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateMail {
    receiver_username: String,
    theme: String,
    text: String,
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

    pub async fn load() -> anyhow::Result<Self> {
        let path = Self::get_path();
        if !path.exists() {
            bail!("No config found");
        }

        let data = tokio::fs::read_to_string(&path).await?;
        let config =
            serde_json::from_str(&data).context("Config is corrupted. Fix it or delete")?;

        Ok(config)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let cli = Cli::parse();
    let client = Client::new();
    let mut config = match AuthConfig::load().await {
        Ok(config) => config,
        Err(_) => AuthConfig { access_token: None },
    };
    let server_ip = "http://localhost:3000";

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
                    .post(format!("{server_ip}/users/auth/register"))
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
                    .post(format!("{server_ip}/users/auth/login"))
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
        Commands::Mail(commands) => match commands {
            MailSubcommands::List(args) => match config.access_token {
                Some(token) => {
                    log::debug!("token: {}", token);
                    let reqwest;
                    // if args.read {
                    //     reqwest = "mail/read"
                    // } else if args.unread {
                    //     reqwest = "mail/unread"
                    // } else if args.sent {
                    //     reqwest = "mail/sent"
                    // } else {
                    reqwest = "mail/all";
                    // }

                    log::debug!("getting response from server...");

                    let response = client
                        .get(format!("{server_ip}/{reqwest}"))
                        .bearer_auth(token)
                        .send()
                        .await?;

                    log::debug!("got response");
                    log::debug!("trying to parse response");

                    if response.status().is_success() {
                        let mails = response.json::<Vec<Mail>>().await?;
                        log::debug!("response got parsed");
                        for (i, mail) in mails.iter().enumerate() {
                            println!(
                                "[{}]: theme: {}, from: {}, to: {}",
                                i, mail.theme, mail.sender, mail.receiver
                            );
                        }
                    } else {
                        log::error!("Response error")
                    }
                }
                None => {
                    println!("You are not authorized. Authorize first.")
                }
            },
            MailSubcommands::Send(args) => {
                if let Some(file) = args.content.file {
                    println!("This function has not been ended. Use -m --message instead")
                } else if let Some(message) = args.content.message {
                    match config.access_token {
                        Some(token) => {
                            let mail = CreateMail {
                                receiver_username: args.receiver,
                                theme: args.theme,
                                text: message,
                            };

                            let response = client
                                .post(format!("{server_ip}/mail/new"))
                                .json(&mail)
                                .bearer_auth(&token)
                                .send()
                                .await?;
                            if response.status().is_success() {
                                println!("Mail sent successfully")
                            } else {
                                match response.status() {
                                    StatusCode::NOT_FOUND => {
                                        println!("Can not find user with such username. Try again.")
                                    }
                                    _ => {
                                        println!("Unexpected error has been occured. Try again.")
                                    }
                                }
                            }
                        }
                        None => {
                            println!("You are not authorized. Authorize first.");
                        }
                    }
                }
            }
            MailSubcommands::Open(args) => match config.access_token {
                Some(token) => {
                    log::debug!("getting response from server...");

                    let response = client
                        .get(format!("{server_ip}/mail/all"))
                        .bearer_auth(token)
                        .send()
                        .await?;

                    log::debug!("got response");
                    log::debug!("trying to parse response");

                    if response.status().is_success() {
                        let mails = response.json::<Vec<Mail>>().await?;
                        log::debug!("response got parsed");

                        let mail: &Mail = match mails.get(args.index as usize) {
                            Some(mail) => mail,
                            None => {
                                println!("No such mail has been found");
                                bail!("No such mail has been found");
                            }
                        };

                        println!("from: {}", mail.sender);
                        println!("to: {}", mail.receiver);
                        println!("theme: {}", mail.theme);
                        println!("text: {}", mail.text);
                    } else {
                        log::error!("Response error")
                    }
                }
                None => {
                    println!("You are not authorized. Authorize first.")
                }
            },
        },
    }

    Ok(())
}
