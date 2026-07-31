use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{BOOL, CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExA, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::Threading::IsWow64Process;

use crate::injector_exceptions::InjectorException;
use crate::memory::Memory;

pub struct ExportedFunction {
    pub name: String,
    pub address: NonZeroUsize,
}

impl ExportedFunction {
    pub fn new(name: &str, address: NonZeroUsize) -> Self {
        ExportedFunction { name: name.to_string(), address }
    }
}

pub fn find_process_id_by_name(process_name: &str) -> Option<u32> {
    let process_name = process_name.to_lowercase();
    let process_name =
        if process_name.ends_with(".exe") { process_name } else { format!("{process_name}.exe") };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    let mut process_id = None;
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
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

            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe {
        CloseHandle(snapshot);
    }

    process_id
}

pub fn get_exported_functions(
    handle: HANDLE,
    mod_address: usize,
) -> Result<Vec<ExportedFunction>, InjectorException> {
    let mut exported_functions = Vec::new();
    let is_64_bit = is_64_bit_process(handle)?;

    let memory = Memory::new(handle)?;
    //nt header offset
    let e_lfanew = memory.read_int(mod_address + 0x3C)? as usize;
    let nt_headers = mod_address + e_lfanew as usize;

    let optional_header = nt_headers + 0x18;
    let data_directory = optional_header + if is_64_bit { 0x70 } else { 0x60 };

    let export_directory = mod_address + memory.read_int(data_directory)? as usize;
    let names = mod_address + memory.read_int(export_directory + 0x20)? as usize;
    let ordinals = mod_address + memory.read_int(export_directory + 0x24)? as usize;
    let functions = mod_address + memory.read_int(export_directory + 0x1C)? as usize;
    let count = memory.read_int(export_directory + 0x18)? as usize;

    for i in 0..count {
        let offset = memory.read_int(names + i as usize * 4)? as usize;
        let name = memory.read_string(mod_address + offset as usize, 32)?;
        let ordinal = memory.read_short(ordinals + i as usize * 2)?;

        let address = NonZeroUsize::new(
            mod_address + memory.read_int(functions + ordinal as usize * 4)? as usize,
        );

        if address.is_some() {
            // SAFETY: Address is guaranteed to be non-zero, so unwrap is safe here.
            exported_functions.push(ExportedFunction::new(&name, address.unwrap()));
        }
    }

    Ok(exported_functions)
}

pub fn get_mono_module(handle: HANDLE) -> Result<Option<usize>, InjectorException> {
    let mut bytes_needed: u32 = 0;

    //get required buffer size
    if unsafe { EnumProcessModulesEx(handle, null_mut(), 0, &mut bytes_needed, LIST_MODULES_ALL) }
        == 0
        || bytes_needed == 0
    {
        return Err(InjectorException::new("Failed to enumerate process modules"));
    }

    //resize buffer
    let count = bytes_needed as usize / size_of::<HMODULE>();
    let mut ptrs: Vec<HMODULE> = vec![null_mut(); count];

    //call with allocated buffer
    if unsafe {
        EnumProcessModulesEx(
            handle,
            ptrs.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    } == 0
    {
        return Err(InjectorException::new("Failed to enumerate process modules"));
    }

    for &module in ptrs.iter() {
        let mut path = vec![0u8; 260];
        let path_len =
            unsafe { GetModuleFileNameExA(handle, module, path.as_mut_ptr(), path.len() as u32) }
                as usize;

        if path_len == 0 {
            continue;
        }

        let path_str = String::from_utf8_lossy(&path[..path_len]).to_lowercase();

        if path_str.contains("mono") {
            let mut info: MODULEINFO =
                MODULEINFO { lpBaseOfDll: null_mut(), SizeOfImage: 0, EntryPoint: null_mut() };

            if unsafe {
                GetModuleInformation(handle, module, &mut info, size_of::<MODULEINFO>() as u32)
            } == 0
            {
                return Err(InjectorException::new("Failed to get module information"));
            }

            let funcs = get_exported_functions(handle, info.lpBaseOfDll as usize)?;

            if funcs.iter().any(|f| f.name == "mono_get_root_domain") {
                return Ok(Some(info.lpBaseOfDll as usize));
            }
        }
    }

    Ok(None)
}

pub fn is_64_bit_process(handle: HANDLE) -> Result<bool, InjectorException> {
    if !cfg!(target_pointer_width = "64") {
        return Ok(false);
    }

    let mut is_wow64 = BOOL::default();
    if unsafe { IsWow64Process(handle, &mut is_wow64) } == 0 {
        Err(InjectorException::new("Failed to check Wow64 status"))
    } else {
        Ok(is_wow64 == 0 && size_of::<usize>() == 8)
    }
}
