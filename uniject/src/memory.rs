use std::collections::HashMap;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};

use crate::injector_exceptions::InjectorException;

const U16_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<u16>()).unwrap();
const I32_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<i32>()).unwrap();
const I64_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<i64>()).unwrap();

#[inline]
pub(crate) fn checked_add(
    address: NonZeroUsize,
    offset: usize,
) -> Result<NonZeroUsize, InjectorException> {
    address.checked_add(offset).ok_or_else(|| InjectorException::new("Memory address overflow"))
}

#[inline]
pub(crate) fn checked_mul(value: usize, multiplier: usize) -> Result<usize, InjectorException> {
    value
        .checked_mul(multiplier)
        .ok_or_else(|| InjectorException::new("Memory arithmetic overflow"))
}

pub struct Memory<H: AsHandle> {
    handle: H,
    allocations: HashMap<NonZeroUsize, NonZeroUsize>,
}

impl<H: AsHandle> Memory<H> {
    pub fn new(process_handle: H) -> Self {
        Memory { handle: process_handle, allocations: HashMap::new() }
    }

    fn raw_handle(&self) -> HANDLE {
        self.handle.as_handle().as_raw_handle() as HANDLE
    }

    pub fn read_string(
        &self,
        address: NonZeroUsize,
        length: usize,
    ) -> Result<String, InjectorException> {
        let mut bytes = Vec::new();
        for _ in 0..length {
            let address = checked_add(address, bytes.len())?;
            let read = self.read_bytes(address, NonZeroUsize::MIN)?[0];
            if read == 0x00 {
                break;
            }
            bytes.push(read);
        }

        String::from_utf8(bytes)
            .map_err(|e| InjectorException::with_inner("Failed to read string", Box::new(e)))
    }

    pub fn read_unicode_string(
        &self,
        address: NonZeroUsize,
        length: usize,
    ) -> Result<String, InjectorException> {
        let Some(length) = NonZeroUsize::new(length) else {
            return Ok(String::new());
        };
        let bytes = self.read_bytes(address, length)?;
        let utf16_units: Vec<u16> =
            bytes.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
        String::from_utf16(&utf16_units).map_err(|e| {
            InjectorException::with_inner("Failed to read Unicode string", Box::new(e))
        })
    }

    pub fn read_ushort(&self, address: NonZeroUsize) -> Result<u16, InjectorException> {
        let bytes = self.read_bytes(address, U16_SIZE)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_int(&self, address: NonZeroUsize) -> Result<i32, InjectorException> {
        let bytes = self.read_bytes(address, I32_SIZE)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_uint(&self, address: NonZeroUsize) -> Result<u32, InjectorException> {
        let bytes = self.read_bytes(address, I32_SIZE)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_long(&self, address: NonZeroUsize) -> Result<i64, InjectorException> {
        let bytes = self.read_bytes(address, I64_SIZE)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(
        &self,
        address: NonZeroUsize,
        size: NonZeroUsize,
    ) -> Result<Vec<u8>, InjectorException> {
        let mut buffer = vec![0u8; size.get()];
        if unsafe {
            ReadProcessMemory(
                self.raw_handle(),
                address.get() as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size.get(),
                std::ptr::null_mut(),
            )
        } != 0
        {
            Ok(buffer)
        } else {
            Err(InjectorException::with_inner(
                "Failed to read process memory",
                Box::new(std::io::Error::last_os_error()),
            ))
        }
    }

    pub fn allocate_and_write(&mut self, data: &[u8]) -> Result<NonZeroUsize, InjectorException> {
        let size = NonZeroUsize::new(data.len())
            .ok_or_else(|| InjectorException::new("Cannot allocate an empty buffer"))?;
        let addr = self.allocate(size)?;
        self.write(addr, data)?;
        Ok(addr)
    }

    pub fn allocate_and_write_int(&mut self, data: i32) -> Result<NonZeroUsize, InjectorException> {
        self.allocate_and_write(&data.to_le_bytes())
    }

    pub fn allocate_and_write_long(
        &mut self,
        data: i64,
    ) -> Result<NonZeroUsize, InjectorException> {
        self.allocate_and_write(&data.to_le_bytes())
    }

    pub fn allocate(&mut self, size: NonZeroUsize) -> Result<NonZeroUsize, InjectorException> {
        let addr = unsafe {
            VirtualAllocEx(
                self.raw_handle(),
                std::ptr::null(),
                size.get(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as usize;

        let addr = NonZeroUsize::new(addr)
            .ok_or_else(|| InjectorException::new("Failed to allocate process memory"))?;
        self.allocations.insert(addr, size);
        Ok(addr)
    }

    pub fn write(&self, address: NonZeroUsize, data: &[u8]) -> Result<(), InjectorException> {
        let Some(size) = NonZeroUsize::new(data.len()) else {
            return Ok(());
        };
        if unsafe {
            WriteProcessMemory(
                self.raw_handle(),
                address.get() as *const std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                size.get(),
                std::ptr::null_mut(),
            )
        } != 0
        {
            Ok(())
        } else {
            Err(InjectorException::new("Failed to write process memory"))
        }
    }
}

impl<H: AsHandle> AsHandle for Memory<H> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}

impl<H: AsHandle> Drop for Memory<H> {
    fn drop(&mut self) {
        for (&address, &size) in &self.allocations {
            unsafe {
                if VirtualFreeEx(
                    self.raw_handle(),
                    address.get() as *mut std::ffi::c_void,
                    size.get(),
                    MEM_DECOMMIT,
                ) == 0
                {
                    eprintln!(
                        "Failed to free memory at address {address:X}: {}",
                        std::io::Error::last_os_error()
                    )
                }
            }
        }
        self.allocations.clear();
    }
}
