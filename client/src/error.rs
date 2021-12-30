use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("allocation failed: {0}")]
    Alloc(u32),

    #[error("failed to map image: {0}")]
    MapImage(ManualMapError),

    #[error("failed to copy image into the target process: {0}")]
    CopyImage(u32),
}

#[derive(Error, Debug)]
pub enum ManualMapError {
    #[error("failed to rebase image ({0})")]
    Rebase(pelite::Error),

    #[error("failed to resolve imports ({0})")]
    Imports(pelite::Error),
}
