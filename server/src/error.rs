use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Failed to rebase image ({0})")]
    Rebase(pelite::Error),

    #[error("Failed to resolve imports ({0})")]
    Imports(pelite::Error),
}
