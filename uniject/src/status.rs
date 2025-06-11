#[derive(Debug, PartialEq, Eq)]
pub enum MonoImageOpenStatus {
    MonoImageOk,
    MonoImageErrorErrno,
    MonoImageMissingAssemblyRef,
    MonoImageInvalid,
}

impl From<i32> for MonoImageOpenStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => MonoImageOpenStatus::MonoImageOk,
            1 => MonoImageOpenStatus::MonoImageErrorErrno,
            2 => MonoImageOpenStatus::MonoImageMissingAssemblyRef,
            3 => MonoImageOpenStatus::MonoImageInvalid,
            _ => MonoImageOpenStatus::MonoImageInvalid,
        }
    }
}
