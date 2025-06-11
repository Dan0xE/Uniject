use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct InjectorException {
    message: String,
    inner: Option<Box<dyn Error>>,
}

impl InjectorException {
    pub fn new(message: &str) -> Self {
        InjectorException { message: message.to_string(), inner: None }
    }

    pub fn with_inner(message: &str, inner: Box<dyn Error>) -> Self {
        InjectorException { message: message.to_string(), inner: Some(inner) }
    }
}

impl fmt::Display for InjectorException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InjectorException: {}", self.message)?;
        if let Some(ref inner) = self.inner {
            write!(f, "\nCaused by: {}", inner)?;
        }
        Ok(())
    }
}

impl Error for InjectorException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.as_deref()
    }
}

impl From<iced_x86::IcedError> for InjectorException {
    fn from(error: iced_x86::IcedError) -> Self {
        InjectorException::new(&format!("Assembly error: {}", error))
    }
}
