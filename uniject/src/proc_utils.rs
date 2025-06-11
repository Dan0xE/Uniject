use std::ffi::CStr;
use std::ptr::null_mut;

use crate::exported_functions::ExportedFunction;
use crate::injector_exceptions::InjectorException;
use crate::memory::Memory;
use winapi::um::psapi::{EnumProcessModulesEx, GetModuleFileNameExA, GetModuleInformation, LIST_MODULES_ALL};
use sysinfo::System;
use winapi::shared::minwindef::{BOOL, DWORD};
use winapi::um::psapi::MODULEINFO;
use winapi::um::winnt::HANDLE;
use winapi::um::wow64apiset::IsWow64Process;

pub fn find_process_id_by_name(process_name: &str) -> Option<u32> {
    let mut system = System::new_all();
    system.refresh_all();

    let x = system
        .processes_by_name(process_name)
        .next()
        .map(|process| process.pid().as_u32());
    x
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
    let is_64_bit = is_64_bit_process(handle)?;
    let size = if is_64_bit { 8 } else { 4 };

    let mut bytes_needed: DWORD = 0;

    //get required buffer size
    let success = unsafe {
        EnumProcessModulesEx(
            handle,
            null_mut(),
            0,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    };

    if success == 0 || bytes_needed == 0 {
        return Err(InjectorException::new(
            "Failed to enumerate process modules",
        ));
    }

    //resize buffer
    let count = bytes_needed as usize / size;
    let mut ptrs = vec![null_mut(); count];

    //call with allocated buffer
    let success = unsafe {
        EnumProcessModulesEx(
            handle,
            ptrs.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            LIST_MODULES_ALL,
        )
    };

    if success == 0 {
        return Err(InjectorException::new(
            "Failed to enumerate process modules",
        ))
    }

    for &module in ptrs.iter() {
        let mut path = vec![0i8; 260];
        unsafe {
            GetModuleFileNameExA(handle, module, path.as_mut_ptr(), 260);
        }

        let path_str = unsafe { CStr::from_ptr(path.as_ptr()) }
            .to_string_lossy()
            .to_lowercase();

        if path_str.contains("mono") {
            let mut info: MODULEINFO = MODULEINFO {
                lpBaseOfDll: null_mut(),
                SizeOfImage: 0,
                EntryPoint: null_mut(),
            };

            let success = unsafe {
                GetModuleInformation(
                    handle,
                    module,
                    &mut info,
                    (size * ptrs.len()) as DWORD,
                )
            };

            if success == 0 {
                return Err(InjectorException::new(&"Failed to get module information"));
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

    let mut is_wow64: BOOL = 0;
    let success = unsafe { IsWow64Process(handle, &mut is_wow64) };

    if success == 0 {
        Err(InjectorException::new("Failed to query Wow64 status"))
    } else {
        Ok(is_wow64 == 0 && size_of::<usize>() == 8)
    }
}
