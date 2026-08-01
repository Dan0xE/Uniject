use std::io;
use std::num::{NonZeroUsize, TryFromIntError};
use std::string::{FromUtf8Error, FromUtf16Error};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("assembly error: {0}")]
    Assembly(#[from] iced_x86::IcedError),

    #[error("failed to decode UTF-8 string: {0}")]
    Utf8(#[from] FromUtf8Error),

    #[error("failed to decode UTF-16 string: {0}")]
    Utf16(#[from] FromUtf16Error),

    #[error("integer conversion failed: {0}")]
    IntegerConversion(#[from] TryFromIntError),

    #[error("{operation}: {source}")]
    Windows {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("could not find a process named {name}")]
    ProcessNotFound { name: String },

    #[error("Mono module not found")]
    MonoModuleNotFound,

    #[error("failed to obtain the address of {name}() from Mono module at {module:#X}")]
    MissingExport { name: &'static str, module: NonZeroUsize },

    #[error("{0}() returned NULL")]
    NullReturn(&'static str),

    #[error("raw assembly cannot be empty")]
    EmptyRawAssembly,

    #[error("class name cannot be empty")]
    EmptyClassName,

    #[error("method name cannot be empty")]
    EmptyMethodName,

    #[error("{operation}() failed: {message}")]
    MonoOperation { operation: &'static str, message: String },

    #[error("the managed method threw an exception: ({class_name}) {message}")]
    ManagedException { class_name: String, message: String },

    #[error("an access violation occurred while executing {0}()")]
    AccessViolation(&'static str),

    #[error("module has a null base address")]
    NullModuleBase,

    #[error("memory address overflow")]
    AddressOverflow,

    #[error("memory arithmetic overflow")]
    ArithmeticOverflow,

    #[error("cannot allocate an empty buffer")]
    EmptyBuffer,
}

pub type Result<T> = std::result::Result<T, Error>;
