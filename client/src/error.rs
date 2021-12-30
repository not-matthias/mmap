use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManualMapError {
    #[error("allocation failed: {0}")]
    Alloc(u32),
}
