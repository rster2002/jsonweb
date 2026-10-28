mod functions;
mod error;

pub use error::JwsError;
pub use functions::sign_compact::sign_compact;
pub use functions::verify_compact::verify_compact;