use std::ffi::{CStr};
use std::mem::size_of;
use std::ptr::null_mut;

use crate::exported_functions::ExportedFunction;
use crate::injector_exceptions::InjectorException;
use crate::memory::Memory;
use windows::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExA, GetModuleInformation, MODULEINFO, LIST_MODULES_ALL};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use sysinfo::{ProcessesToUpdate, System};
use windows::core::BOOL;
use windows::Win32::System::Threading::IsWow64Process;

pub fn find_process_id_by_name(process_name: &str) -> Option<u32> {
    let process_name_lower = if process_name.to_lowercase().ends_with(".exe") {
        process_name.to_lowercase()
    } else {
        format!("{}.exe", process_name.to_lowercase())
    };

    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);

    system
        .processes()
        .values()
        .find(|process| {
            process.name().to_string_lossy().to_lowercase() == process_name_lower
        })
        .map(|process| process.pid().as_u32())
}

pub fn get_exported_functions(
    handle: HANDLE,
    mod_address: usize,
) -> Result<Vec<ExportedFunction>, InjectorException> {
    let mut exported_functions = Vec::new();
    let is_64_bit = is_64_bit_process(handle)?;

    let memory = Memory::new(handle).map_err(|err| {
        InjectorException::with_inner("Failed to create memory handler", Box::new(err))
    })?;

    //nt header offset
    let e_lfanew = memory.read_int(mod_address + 0x3C).map_err(|err| {
        InjectorException::with_inner("Failed to read NT headers offset", Box::new(err))
    })?;
    let nt_headers = mod_address + e_lfanew as usize;

    let optional_header = nt_headers + 0x18;
    let data_directory = optional_header + if is_64_bit { 0x70 } else { 0x60 };

    let export_directory = mod_address
        + memory.read_int(data_directory).map_err(|err| {
            InjectorException::with_inner("Failed to read export directory", Box::new(err))
        })? as usize;

    let names = mod_address
        + memory.read_int(export_directory + 0x20).map_err(|err| {
            InjectorException::with_inner("Failed to read names pointer", Box::new(err))
        })? as usize;
    let ordinals = mod_address
        + memory.read_int(export_directory + 0x24).map_err(|err| {
            InjectorException::with_inner("Failed to read ordinals pointer", Box::new(err))
        })? as usize;
    let functions = mod_address
        + memory.read_int(export_directory + 0x1C).map_err(|err| {
            InjectorException::with_inner("Failed to read functions pointer", Box::new(err))
        })? as usize;
    let count = memory.read_int(export_directory + 0x18).map_err(|err| {
        InjectorException::with_inner("Failed to read functions count", Box::new(err))
    })?;

    for i in 0..count {
        let offset = memory.read_int(names + i as usize * 4).map_err(|err| {
            InjectorException::with_inner("Failed to read function name offset", Box::new(err))
        })?;
        let name = memory
            .read_string(mod_address + offset as usize, 32)
            .map_err(|err| {
                InjectorException::with_inner("Failed to read function name", Box::new(err))
            })?;
        let ordinal = memory
            .read_short(ordinals + i as usize * 2)
            .map_err(|err| {
                InjectorException::with_inner("Failed to read function ordinal", Box::new(err))
            })?;
        let address = mod_address
            + memory
                .read_int(functions + ordinal as usize * 4)
                .map_err(|err| {
                    InjectorException::with_inner("Failed to read function address", Box::new(err))
                })? as usize;

        if address != 0 {
            exported_functions.push(ExportedFunction::new(&name, address));
        }
    }

    Ok(exported_functions)
}

pub fn get_mono_module(handle: HANDLE) -> Result<Option<usize>, InjectorException> {
    let mut bytes_needed: u32 = 0;

    //get required buffer size
   if unsafe {
        EnumProcessModulesEx(
            handle,
            null_mut(),
            0,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    }.is_err() || bytes_needed == 0 {
        return Err(InjectorException::new(
            "Failed to enumerate process modules",
        ));
    }

    //resize buffer
    let count = bytes_needed as usize / size_of::<HMODULE>();
    let mut ptrs: Vec<HMODULE> = vec![HMODULE::default(); count];

    //call with allocated buffer
    if unsafe {
        EnumProcessModulesEx(
            handle,
            ptrs.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    }.is_err() {
        return Err(InjectorException::new(
            "Failed to enumerate process modules",
        ))
    }

    for &module in ptrs.iter() {
        let mut path = vec![0u8; 260];
        unsafe {
            GetModuleFileNameExA(Some(handle), Some(module), &mut path);
        }

        if path.is_empty() {
            continue;
        }

        let path_str = unsafe { CStr::from_ptr(path.as_ptr() as *const i8) }
            .to_string_lossy()
            .to_lowercase();

        if path_str.contains("mono") {
            let mut info: MODULEINFO = MODULEINFO {
                lpBaseOfDll: null_mut(),
                SizeOfImage: 0,
                EntryPoint: null_mut(),
            };

            if unsafe {
                GetModuleInformation(
                    handle,
                    module,
                    &mut info,
                    size_of::<MODULEINFO>() as u32,
                )
            }.is_err() {
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
    if unsafe { IsWow64Process(handle, &mut is_wow64)}.is_err() {
        Err(InjectorException::new("Failed to check Wow64 status")) 
    } else {
        Ok(!is_wow64.as_bool() && size_of::<usize>() == 8)
    }
}
