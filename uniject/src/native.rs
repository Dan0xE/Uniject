use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};
use winapi::um::psapi::MODULEINFO;
use winapi::um::winnt::HANDLE;

// pub struct ModuleInfo {
//     pub lp_base_of_dll: usize,
//     pub size_of_image: i32,
//     pub entry_point: usize,
// }

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum ModuleFilter {
    // ListModulesDefault = 0x0,
    // ListModules32Bit = 0x01,
    // ListModules64Bit = 0x02,
    ListModulesAll = 0x03,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum AllocationType {
    MemCommit = 0x00001000,
    MemReserve = 0x00002000,
    // MemReset = 0x00080000,
    // MemResetUndo = 0x1000000,
    // MemLargePages = 0x20000000,
    // MemPhysical = 0x00400000,
    // MemTopDown = 0x00100000,
}

bitflags::bitflags! {
    pub struct MemoryProtection: u32 {
        const PAGE_EXECUTE = 0x10;
        const PAGE_EXECUTE_READ = 0x20;
        const PAGE_EXECUTE_READWRITE = 0x40;
        const PAGE_EXECUTE_WRITECOPY = 0x80;
        const PAGE_NOACCESS = 0x01;
        const PAGE_READONLY = 0x02;
        const PAGE_READWRITE = 0x04;
        const PAGE_WRITECOPY = 0x08;
        const PAGE_TARGETS_INVALID = 0x40000000;
        const PAGE_TARGETS_NO_UPDATE = Self::PAGE_TARGETS_INVALID.bits();
        const PAGE_GUARD = 0x100;
        const PAGE_NOCACHE = 0x200;
        const PAGE_WRITECOMBINE = 0x400;
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum MemoryFreeType {
    MemDecommit = 0x4000,
    // MemRelease = 0x8000,
}

// #[repr(u32)]
// #[derive(Clone, Copy, Debug)]
// pub enum ThreadCreationFlags {
//     None = 0,
//     CreateSuspended = 0x00000004,
//     StackSizeParamIsAReservation = 0x00010000,
// }

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum WaitResult {
    // WaitAbandoned = 0x00000080,
    // WaitObject0 = 0x00000000,
    // WaitTimeout = 0x00000102,
    WaitFailed = 0xFFFFFFFF,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum ProcessAccessRights {
    ProcessAllAccess = 0x1FFFFF,
    // ProcessCreateProcess = 0x0080,
    // ProcessCreateThread = 0x0002,
    // ProcessDupHandle = 0x0040,
    // ProcessQueryInformation = 0x0400,
    // ProcessQueryLimitedInformation = 0x1000,
    // ProcessSetInformation = 0x0200,
    // ProcessSetQuota = 0x0100,
    // ProcessSuspendResume = 0x0800,
    // ProcessTerminate = 0x0001,
    // ProcessVmOperation = 0x0008,
    // ProcessVmRead = 0x0010,
    // ProcessVmWrite = 0x0020,
    // Synchronize = 0x00100000,
}

unsafe extern "system" {
    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;

    pub fn CloseHandle(hObject: HANDLE) -> BOOL;

    pub fn IsWow64Process(hProcess: HANDLE, wow64Process: *mut BOOL) -> BOOL;

    pub fn EnumProcessModulesEx(
        hProcess: HANDLE,
        lphModule: *mut LPVOID,
        cb: DWORD,
        lpcbNeeded: *mut DWORD,
        dwFilterFlag: DWORD,
    ) -> BOOL;

    // pub fn GetModuleFileNameEx(
    //     hProcess: HANDLE,
    //     hModule: HANDLE,
    //     lpBaseName: *mut u8,
    //     nSize: DWORD,
    // ) -> DWORD;

    pub fn GetModuleFileNameExA(
        hProcess: HANDLE,
        hModule: HANDLE,
        lpBaseName: *mut i8,
        nSize: DWORD,
    ) -> DWORD;

    pub fn GetModuleInformation(
        hProcess: HANDLE,
        hModule: HANDLE,
        lpmodinfo: *mut MODULEINFO,
        cb: DWORD,
    ) -> BOOL;

    pub fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: LPVOID,
        lpBuffer: LPVOID,
        nSize: DWORD,
        lpNumberOfBytesWritten: *mut DWORD,
    ) -> BOOL;

    pub fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: LPVOID,
        lpBuffer: LPVOID,
        nSize: DWORD,
        lpNumberOfBytesRead: *mut DWORD,
    ) -> BOOL;

    pub fn VirtualAllocEx(
        hProcess: HANDLE,
        lpAddress: LPVOID,
        dwSize: DWORD,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> LPVOID;

    pub fn VirtualFreeEx(
        hProcess: HANDLE,
        lpAddress: LPVOID,
        dwSize: DWORD,
        dwFreeType: DWORD,
    ) -> BOOL;

    pub fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: LPVOID,
        dwStackSize: DWORD,
        lpStartAddress: LPVOID,
        lpParameter: LPVOID,
        dwCreationFlags: DWORD,
        lpThreadId: *mut DWORD,
    ) -> HANDLE;

    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
}
