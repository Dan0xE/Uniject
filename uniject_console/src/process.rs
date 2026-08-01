use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

pub(crate) fn find_process_id_by_name(process_name: &str) -> io::Result<u32> {
    let requested_name = process_name.to_owned();
    let process_name = process_name.to_lowercase();
    let process_name =
        if process_name.ends_with(".exe") { process_name } else { format!("{process_name}.exe") };

    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateToolhelp32Snapshot returned a valid, owned handle.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot) };

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot.as_raw_handle() as HANDLE, &mut entry) } != 0 {
        loop {
            let name_len = entry
                .szExeFile
                .iter()
                .position(|&character| character == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

            if name == process_name {
                return Ok(entry.th32ProcessID);
            }

            if unsafe { Process32NextW(snapshot.as_raw_handle() as HANDLE, &mut entry) } == 0 {
                break;
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("could not find a process named {requested_name}"),
    ))
}
