use std::collections::HashMap;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};

use crate::error::{Error, Result};

const U16_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<u16>()).unwrap();
const I32_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<i32>()).unwrap();
const U64_SIZE: NonZeroUsize = NonZeroUsize::new(size_of::<u64>()).unwrap();

#[inline]
pub(crate) fn checked_add(address: NonZeroUsize, offset: usize) -> Result<NonZeroUsize> {
    address.checked_add(offset).ok_or(Error::AddressOverflow)
}

#[inline]
pub(crate) fn checked_mul(value: usize, multiplier: usize) -> Result<usize> {
    value.checked_mul(multiplier).ok_or(Error::ArithmeticOverflow)
}

pub(crate) struct Memory<H: AsHandle> {
    handle: H,
    allocations: HashMap<NonZeroUsize, NonZeroUsize>,
}

impl<H: AsHandle> Memory<H> {
    pub(crate) fn new(process_handle: H) -> Self {
        Memory { handle: process_handle, allocations: HashMap::new() }
    }

    fn raw_handle(&self) -> HANDLE {
        self.handle.as_handle().as_raw_handle() as HANDLE
    }

    pub(crate) fn read_string(&self, address: NonZeroUsize, length: usize) -> Result<String> {
        let mut bytes = Vec::new();
        for _ in 0..length {
            let address = checked_add(address, bytes.len())?;
            let read = self.read_bytes(address, NonZeroUsize::MIN)?[0];
            if read == 0x00 {
                break;
            }
            bytes.push(read);
        }

        Ok(String::from_utf8(bytes)?)
    }

    pub(crate) fn read_ushort(&self, address: NonZeroUsize) -> Result<u16> {
        let bytes = self.read_bytes(address, U16_SIZE)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn read_int(&self, address: NonZeroUsize) -> Result<i32> {
        let bytes = self.read_bytes(address, I32_SIZE)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_uint(&self, address: NonZeroUsize) -> Result<u32> {
        let bytes = self.read_bytes(address, I32_SIZE)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn read_pointer(&self, address: NonZeroUsize, is_64_bit: bool) -> Result<usize> {
        if !is_64_bit {
            return Ok(self.read_uint(address)? as usize);
        }

        let bytes = self.read_bytes(address, U64_SIZE)?;
        Ok(usize::try_from(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))?)
    }

    pub(crate) fn read_bytes(&self, address: NonZeroUsize, size: NonZeroUsize) -> Result<Vec<u8>> {
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
            Err(Error::Windows {
                operation: "failed to read process memory",
                source: std::io::Error::last_os_error(),
            })
        }
    }

    pub(crate) fn allocate_and_write(&mut self, data: &[u8]) -> Result<NonZeroUsize> {
        let size = NonZeroUsize::new(data.len()).ok_or(Error::EmptyBuffer)?;
        let addr = self.allocate(size)?;
        self.write(addr, data)?;
        Ok(addr)
    }

    fn allocate(&mut self, size: NonZeroUsize) -> Result<NonZeroUsize> {
        let addr = unsafe {
            VirtualAllocEx(
                self.raw_handle(),
                std::ptr::null(),
                size.get(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as usize;

        let addr = NonZeroUsize::new(addr).ok_or_else(|| Error::Windows {
            operation: "failed to allocate process memory",
            source: std::io::Error::last_os_error(),
        })?;
        self.allocations.insert(addr, size);
        Ok(addr)
    }

    fn write(&self, address: NonZeroUsize, data: &[u8]) -> Result<()> {
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
            Err(Error::Windows {
                operation: "failed to write process memory",
                source: std::io::Error::last_os_error(),
            })
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
        for &address in self.allocations.keys() {
            unsafe {
                if VirtualFreeEx(
                    self.raw_handle(),
                    address.get() as *mut std::ffi::c_void,
                    0,
                    MEM_RELEASE,
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
