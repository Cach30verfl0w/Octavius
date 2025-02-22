// Copyright 2025 Cedric Hammes
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod protocols;

use std::fs;
use std::process::exit;
use colorful::{Color, Colorful};
use log::{error, info, LevelFilter};
use sea_orm::{ConnectOptions, DatabaseConnection};
use simple_logger::SimpleLogger;

async fn connect_database(database_url: &str) -> anyhow::Result<DatabaseConnection> {
    if database_url.starts_with("sqlite://") {
        let path = database_url.replace("sqlite://", "");
        if !fs::exists(&path).unwrap_or(false) {
            fs::write(path, &[])?;
        }
    }
    Ok(sea_orm::Database::connect(ConnectOptions::from(database_url)).await?)
}

#[rocket::main]
async fn main() {
    if let Err(error) = SimpleLogger::new().with_level(LevelFilter::Info).init() {
        println!("Unable to initialize logging => {}", error);
        exit(-1);
    }

    let header = r#"   ____       __              _
  / __ \_____/ /_____ __   __(_)_  _______
 / / / / ___/ __/ __ `/ | / / / / / / ___/
/ /_/ / /__/ /_/ /_/ /| |/ / / /_/ (__  )
\____/\___/\__/\__,_/ |___/_/\__,_/____/
   Modern BGP Router by Cach30verfl0w"#;
    println!("{}\n", header.gradient(Color::Green).bold());

    let database_url = "sqlite://database.db"; // TODO: replace with configuration file (if no config, wizard on start of the router)
    let database = connect_database(&database_url).await;
    if let Err(error) = database {
        error!("Unable to establish connection to database => {}", error);
        exit(-1);
    }

    let database = database.unwrap();
    // TODO: Run migration for all tables
    // TODO: (Only if no users present) Create user database

    info!("Starting REST API for control server");
    let rocket = rocket::build();
    if let Err(error) = rocket.launch().await {
        error!("Unable to initialize REST API => {}", error);
        exit(-1);
    }
}
