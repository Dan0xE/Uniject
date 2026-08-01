use std::mem::size_of;
use std::num::NonZeroUsize;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{BOOL, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExA, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::Threading::IsWow64Process;

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

pub fn find_process_id_by_name(process_name: &str) -> Result<u32> {
    let requested_name = process_name.to_owned();
    let process_name = process_name.to_lowercase();
    let process_name =
        if process_name.ends_with(".exe") { process_name } else { format!("{process_name}.exe") };

    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(Error::Windows {
            operation: "failed to create process snapshot",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: CreateToolhelp32Snapshot returned a valid, owned handle.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot) };

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let mut process_id = None;
    if unsafe { Process32FirstW(snapshot.as_raw_handle() as HANDLE, &mut entry) } != 0 {
        loop {
            let name_len = entry
                .szExeFile
                .iter()
                .position(|&character| character == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

            if name == process_name {
                process_id = Some(entry.th32ProcessID);
                break;
            }

            if unsafe { Process32NextW(snapshot.as_raw_handle() as HANDLE, &mut entry) } == 0 {
                break;
            }
        }
    }

    process_id.ok_or(Error::ProcessNotFound { name: requested_name })
}

fn get_exported_functions(
    handle: BorrowedHandle<'_>,
    mod_address: NonZeroUsize,
    is_64_bit: bool,
) -> Result<Vec<ExportedFunction>> {
    let mut exported_functions = Vec::new();

    let memory = Memory::new(handle);
    //nt header offset
    let e_lfanew = usize::try_from(memory.read_int(checked_add(mod_address, 0x3C)?)?)?;
    let nt_headers = checked_add(mod_address, e_lfanew)?;

    let optional_header = checked_add(nt_headers, 0x18)?;
    let data_directory = checked_add(optional_header, if is_64_bit { 0x70 } else { 0x60 })?;

    let export_directory = checked_add(mod_address, memory.read_uint(data_directory)? as usize)?;
    let names =
        checked_add(mod_address, memory.read_uint(checked_add(export_directory, 0x20)?)? as usize)?;
    let ordinals =
        checked_add(mod_address, memory.read_uint(checked_add(export_directory, 0x24)?)? as usize)?;
    let functions =
        checked_add(mod_address, memory.read_uint(checked_add(export_directory, 0x1C)?)? as usize)?;
    let count = memory.read_uint(checked_add(export_directory, 0x18)?)? as usize;

    for i in 0..count {
        let name_offset = checked_mul(i, 4)?;
        let offset = memory.read_uint(checked_add(names, name_offset)?)? as usize;
        let name = memory.read_string(checked_add(mod_address, offset)?, 32)?;

        let ordinal_offset = checked_mul(i, 2)?;
        let ordinal = memory.read_ushort(checked_add(ordinals, ordinal_offset)?)?;

        let function_offset = checked_mul(usize::from(ordinal), 4)?;
        let address = checked_add(
            mod_address,
            memory.read_uint(checked_add(functions, function_offset)?)? as usize,
        )?;
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

pub(crate) fn is_64_bit_process(handle: BorrowedHandle<'_>) -> Result<bool> {
    if !cfg!(target_pointer_width = "64") {
        return Ok(false);
    }

    let mut is_wow64 = BOOL::default();
    if unsafe { IsWow64Process(handle.as_raw_handle() as HANDLE, &mut is_wow64) } == 0 {
        Err(Error::Windows {
            operation: "failed to check Wow64 status",
            source: std::io::Error::last_os_error(),
        })
    } else {
        Ok(is_wow64 == 0 && size_of::<usize>() == 8)
    }
}
