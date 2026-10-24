#![doc = include_str!("../README.md")]

#[cfg(not(windows))]
compile_error!("uniject only supports Windows targets");

mod assembler;
mod error;
mod injector;
mod memory;
mod process;

pub use error::{Error, Result};
pub use injector::Injector;
