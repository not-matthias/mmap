use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("allocation failed: {0}")]
    Alloc(u32),
}

#[derive(Error, Debug)]
pub enum ManualMapError {
    #[error("Failed to rebase image ({0})")]
    Rebase(pelite::Error),

    #[error("Failed to resolve imports ({0})")]
    Imports(pelite::Error),
}
