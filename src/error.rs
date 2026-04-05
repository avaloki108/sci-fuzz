//! Error types for sci-fuzz.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("EVM error: {0}")]
    Evm(String),

    #[error("snapshot error: {0}")]
    Snapshot(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("oracle error: {0}")]
    Oracle(String),

    #[error("project error: {0}")]
    Project(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
