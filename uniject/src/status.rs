#[derive(Debug, PartialEq, Eq)]
pub enum MonoImageOpenStatus {
    Ok,
    ErrorErrno,
    MissingAssemblyRef,
    Invalid,
}

impl From<i32> for MonoImageOpenStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => MonoImageOpenStatus::Ok,
            1 => MonoImageOpenStatus::ErrorErrno,
            2 => MonoImageOpenStatus::MissingAssemblyRef,
            3 => MonoImageOpenStatus::Invalid,
            _ => MonoImageOpenStatus::Invalid,
        }
    }
}
