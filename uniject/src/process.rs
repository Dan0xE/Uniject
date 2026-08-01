use std::mem::size_of;
use std::num::NonZeroUsize;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExA, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};

use crate::error::{Error, Result};
use crate::memory::{Memory, checked_add, checked_mul};

pub(crate) struct ExportedFunction {
    pub(crate) name: String,
    pub(crate) address: NonZeroUsize,
}

pub(crate) struct MonoModule {
    pub(crate) address: NonZeroUsize,
    pub(crate) exports: Vec<ExportedFunction>,
}

fn get_exported_functions(
    handle: BorrowedHandle<'_>,
    mod_address: NonZeroUsize,
    is_64_bit: bool,
) -> Result<Vec<ExportedFunction>> {
    let memory = Memory::new(handle);
    //nt header offset
    let e_lfanew = usize::try_from(memory.read_int(checked_add(mod_address, 0x3C)?)?)?;
    let nt_headers = checked_add(mod_address, e_lfanew)?;

    let optional_header = checked_add(nt_headers, 0x18)?;
    let data_directory = checked_add(optional_header, if is_64_bit { 0x70 } else { 0x60 })?;

    let export_directory = checked_add(mod_address, memory.read_uint(data_directory)? as usize)?;
    let names_address =
        checked_add(mod_address, memory.read_uint(checked_add(export_directory, 0x20)?)? as usize)?;
    let ordinals_address =
        checked_add(mod_address, memory.read_uint(checked_add(export_directory, 0x24)?)? as usize)?;
    let functions_address =
        checked_add(mod_address, memory.read_uint(checked_add(export_directory, 0x1C)?)? as usize)?;
    let function_count = memory.read_uint(checked_add(export_directory, 0x14)?)? as usize;
    let name_count = memory.read_uint(checked_add(export_directory, 0x18)?)? as usize;

    if name_count == 0 {
        return Ok(Vec::new());
    }

    let names_size = NonZeroUsize::new(checked_mul(name_count, size_of::<u32>())?)
        .ok_or(Error::ArithmeticOverflow)?;
    let ordinals_size = NonZeroUsize::new(checked_mul(name_count, size_of::<u16>())?)
        .ok_or(Error::ArithmeticOverflow)?;
    let names = memory.read_bytes(names_address, names_size)?;
    let ordinals = memory.read_bytes(ordinals_address, ordinals_size)?;
    let functions_size = checked_mul(function_count, size_of::<u32>())?;
    let functions = match NonZeroUsize::new(functions_size) {
        Some(size) => memory.read_bytes(functions_address, size)?,
        None => Vec::new(),
    };

    let mut exported_functions = Vec::with_capacity(name_count);
    for (name, ordinal) in
        names.chunks_exact(size_of::<u32>()).zip(ordinals.chunks_exact(size_of::<u16>()))
    {
        let offset = u32::from_le_bytes([name[0], name[1], name[2], name[3]]) as usize;
        let name = memory.read_string(checked_add(mod_address, offset)?, 32)?;

        let ordinal = u16::from_le_bytes([ordinal[0], ordinal[1]]);
        if usize::from(ordinal) >= function_count {
            return Err(Error::InvalidExportOrdinal { ordinal, function_count });
        }

        let function_offset = checked_mul(usize::from(ordinal), size_of::<u32>())?;
        let function_rva = u32::from_le_bytes([
            functions[function_offset],
            functions[function_offset + 1],
            functions[function_offset + 2],
            functions[function_offset + 3],
        ]);
        let address = checked_add(mod_address, function_rva as usize)?;
        exported_functions.push(ExportedFunction { name, address });
    }

    Ok(exported_functions)
}

pub(crate) fn get_mono_module(
    handle: BorrowedHandle<'_>,
    is_64_bit: bool,
) -> Result<Option<MonoModule>> {
    let mut bytes_needed: u32 = 0;
    let raw_handle = handle.as_raw_handle() as HANDLE;

    //get required buffer size
    if unsafe {
        EnumProcessModulesEx(raw_handle, null_mut(), 0, &mut bytes_needed, LIST_MODULES_ALL)
    } == 0
        || bytes_needed == 0
    {
        return Err(Error::Windows {
            operation: "failed to enumerate process modules",
            source: std::io::Error::last_os_error(),
        });
    }

    //resize buffer
    let count = bytes_needed as usize / size_of::<HMODULE>();
    let mut ptrs: Vec<HMODULE> = vec![null_mut(); count];

    //call with allocated buffer
    if unsafe {
        EnumProcessModulesEx(
            raw_handle,
            ptrs.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    } == 0
    {
        return Err(Error::Windows {
            operation: "failed to enumerate process modules",
            source: std::io::Error::last_os_error(),
        });
    }

    for &module in ptrs.iter() {
        let mut path = vec![0u8; 260];
        let path_len = unsafe {
            GetModuleFileNameExA(raw_handle, module, path.as_mut_ptr(), path.len() as u32)
        } as usize;

        if path_len == 0 {
            continue;
        }

        let path_str = String::from_utf8_lossy(&path[..path_len]).to_lowercase();

        if path_str.contains("mono") {
            let mut info: MODULEINFO =
                MODULEINFO { lpBaseOfDll: null_mut(), SizeOfImage: 0, EntryPoint: null_mut() };

            if unsafe {
                GetModuleInformation(raw_handle, module, &mut info, size_of::<MODULEINFO>() as u32)
            } == 0
            {
                return Err(Error::Windows {
                    operation: "failed to get module information",
                    source: std::io::Error::last_os_error(),
                });
            }

            let module_address =
                NonZeroUsize::new(info.lpBaseOfDll as usize).ok_or(Error::NullModuleBase)?;
            let exports = get_exported_functions(handle, module_address, is_64_bit)?;

            if exports.iter().any(|export| export.name == "mono_get_root_domain") {
                return Ok(Some(MonoModule { address: module_address, exports }));
            }
        }
    }

    Ok(None)
}
