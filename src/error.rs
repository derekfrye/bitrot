use thiserror::Error;

// taken from https://nick.groenen.me/posts/rust-error-handling/
#[derive(Error, Debug)]
pub enum AppError {
    // /// Represents an empty source. For example, an empty text file being given
    // /// as input to `count_words()`.
    // #[error("Missing MD5")]
    // EmptySource,

    // // /// Represents a failure to read from input.
    // // #[error("Mismatch MD5")]
    // // MismatchError,
    
    // ReadError { source: std::io::Error },
    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}