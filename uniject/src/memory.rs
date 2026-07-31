use std::collections::HashMap;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};

use crate::injector_exceptions::InjectorException;

pub struct Memory {
    handle: HANDLE,
    allocations: HashMap<usize, usize>,
}

impl Memory {
    pub fn new(process_handle: HANDLE) -> Result<Self, InjectorException> {
        if process_handle.is_null() {
            Err(InjectorException::new("Invalid process handle"))
        } else {
            Ok(Memory { handle: process_handle, allocations: HashMap::new() })
        }
    }

    pub fn read_string(&self, address: usize, length: usize) -> Result<String, InjectorException> {
        let mut bytes = Vec::new();
        for _ in 0..length {
            let read = self.read_bytes(address + bytes.len(), 1)?[0];
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
        address: usize,
        length: usize,
    ) -> Result<String, InjectorException> {
        let bytes = self.read_bytes(address, length)?;
        let utf16_units: Vec<u16> =
            bytes.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
        String::from_utf16(&utf16_units).map_err(|e| {
            InjectorException::with_inner("Failed to read Unicode string", Box::new(e))
        })
    }

    pub fn read_short(&self, address: usize) -> Result<i16, InjectorException> {
        let bytes = self.read_bytes(address, 2)?;
        Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_int(&self, address: usize) -> Result<i32, InjectorException> {
        let bytes = self.read_bytes(address, 4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_long(&self, address: usize) -> Result<i64, InjectorException> {
        let bytes = self.read_bytes(address, 8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&self, address: usize, size: usize) -> Result<Vec<u8>, InjectorException> {
        let mut buffer = vec![0u8; size];
        if unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                size,
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

    pub fn allocate_and_write(&mut self, data: &[u8]) -> Result<usize, InjectorException> {
        let addr = self.allocate(data.len())?;
        self.write(addr, data)?;
        Ok(addr)
    }

    pub fn allocate_and_write_int(&mut self, data: i32) -> Result<usize, InjectorException> {
        self.allocate_and_write(&data.to_le_bytes())
    }

    pub fn allocate_and_write_long(&mut self, data: i64) -> Result<usize, InjectorException> {
        self.allocate_and_write(&data.to_le_bytes())
    }

    pub fn allocate(&mut self, size: usize) -> Result<usize, InjectorException> {
        let addr = unsafe {
            VirtualAllocEx(
                self.handle,
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as usize;

        if addr == 0 {
            Err(InjectorException::new("Failed to allocate process memory"))
        } else {
            self.allocations.insert(addr, size);
            Ok(addr)
        }
    }

    pub fn write(&self, address: usize, data: &[u8]) -> Result<(), InjectorException> {
        let size = data.len();
        if unsafe {
            WriteProcessMemory(
                self.handle,
                address as *const std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                size,
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

impl Drop for Memory {
    fn drop(&mut self) {
        for (&address, &size) in &self.allocations {
            unsafe {
                if VirtualFreeEx(self.handle, address as *mut std::ffi::c_void, size, MEM_DECOMMIT)
                    == 0
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
