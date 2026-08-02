#![doc = include_str!("../README.md")]

#[cfg(not(windows))]
compile_error!("uniject only supports Windows targets");

#[cfg(windows)]
mod assembler;
#[cfg(windows)]
mod error;
#[cfg(windows)]
mod injector;
#[cfg(windows)]
mod memory;
#[cfg(windows)]
mod process;

#[cfg(windows)]
pub use error::{Error, Result};
#[cfg(windows)]
pub use injector::Injector;
