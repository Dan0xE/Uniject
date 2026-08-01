use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, IsWow64Process, OpenProcess, PROCESS_ALL_ACCESS, WaitForSingleObject,
};
use windows_sys::core::BOOL;

use crate::assembler::Assembler;
use crate::error::{Error, Result};
use crate::memory::{Memory, checked_add, checked_mul};
use crate::process::get_mono_module;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MonoImageOpenStatus {
    Ok,
    ErrorErrno,
    MissingAssemblyRef,
    Invalid,
}

impl From<i32> for MonoImageOpenStatus {
    fn from(value: i32) -> Self {
        match value {
            0 => MonoImageOpenStatus::Ok,
            1 => MonoImageOpenStatus::ErrorErrno,
            2 => MonoImageOpenStatus::MissingAssemblyRef,
            _ => MonoImageOpenStatus::Invalid,
        }
    }
}

pub struct Injector {
    memory: Memory<OwnedHandle>,
    exports: HashMap<&'static str, NonZeroUsize>,
    root_domain: Option<NonZeroUsize>,
    attach: bool,
    mono_module: NonZeroUsize,
    is_64_bit: bool,
}

impl Injector {
    const MONO_GET_ROOT_DOMAIN: &'static str = "mono_get_root_domain";
    const MONO_THREAD_ATTACH: &'static str = "mono_thread_attach";
    const MONO_IMAGE_OPEN_FROM_DATA: &'static str = "mono_image_open_from_data";
    const MONO_ASSEMBLY_LOAD_FROM_FULL: &'static str = "mono_assembly_load_from_full";
    const MONO_ASSEMBLY_GET_IMAGE: &'static str = "mono_assembly_get_image";
    const MONO_CLASS_FROM_NAME: &'static str = "mono_class_from_name";
    const MONO_CLASS_GET_METHOD_FROM_NAME: &'static str = "mono_class_get_method_from_name";
    const MONO_RUNTIME_INVOKE: &'static str = "mono_runtime_invoke";
    const MONO_ASSEMBLY_CLOSE: &'static str = "mono_assembly_close";
    const MONO_IMAGE_STRERROR: &'static str = "mono_image_strerror";
    const MONO_OBJECT_GET_CLASS: &'static str = "mono_object_get_class";
    const MONO_CLASS_GET_NAME: &'static str = "mono_class_get_name";

    pub fn new(process_id: u32) -> Result<Self> {
        let raw_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };

        if raw_handle.is_null() || raw_handle == INVALID_HANDLE_VALUE {
            return Err(Error::Windows {
                operation: "failed to open process",
                source: std::io::Error::last_os_error(),
            });
        }
        // SAFETY: OpenProcess returned a valid, owned handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw_handle) };

        let is_64_bit = if cfg!(target_pointer_width = "64") {
            let mut is_wow64 = BOOL::default();
            if unsafe {
                IsWow64Process(handle.as_handle().as_raw_handle() as HANDLE, &mut is_wow64)
            } == 0
            {
                return Err(Error::Windows {
                    operation: "failed to check Wow64 status",
                    source: std::io::Error::last_os_error(),
                });
            }
            is_wow64 == 0
        } else {
            false
        };

        let mono_module =
            get_mono_module(handle.as_handle(), is_64_bit)?.ok_or(Error::MonoModuleNotFound)?;

        let exports = [
            Self::MONO_GET_ROOT_DOMAIN,
            Self::MONO_THREAD_ATTACH,
            Self::MONO_IMAGE_OPEN_FROM_DATA,
            Self::MONO_ASSEMBLY_LOAD_FROM_FULL,
            Self::MONO_ASSEMBLY_GET_IMAGE,
            Self::MONO_CLASS_FROM_NAME,
            Self::MONO_CLASS_GET_METHOD_FROM_NAME,
            Self::MONO_RUNTIME_INVOKE,
            Self::MONO_ASSEMBLY_CLOSE,
            Self::MONO_IMAGE_STRERROR,
            Self::MONO_OBJECT_GET_CLASS,
            Self::MONO_CLASS_GET_NAME,
        ]
        .into_iter()
        .map(|name| {
            mono_module
                .exports
                .iter()
                .find(|export| export.name == name)
                .map(|export| (name, export.address))
                .ok_or(Error::MissingExport { name, module: mono_module.address })
        })
        .collect::<Result<HashMap<_, _>>>()?;

        let memory = Memory::new(handle);

        Ok(Injector {
            memory,
            exports,
            root_domain: None,
            attach: false,
            mono_module: mono_module.address,
            is_64_bit,
        })
    }

    pub fn is_64_bit(&self) -> bool {
        self.is_64_bit
    }

    #[inline]
    fn export(&self, name: &'static str) -> Result<NonZeroUsize> {
        self.exports
            .get(name)
            .copied()
            .ok_or(Error::MissingExport { name, module: self.mono_module })
    }

    pub fn inject(
        &mut self,
        raw_assembly: &[u8],
        namespace: &str,
        class_name: &str,
        method_name: &str,
    ) -> Result<NonZeroUsize> {
        if raw_assembly.is_empty() {
            return Err(Error::EmptyRawAssembly);
        }

        if class_name.is_empty() {
            return Err(Error::EmptyClassName);
        }

        if method_name.is_empty() {
            return Err(Error::EmptyMethodName);
        }

        self.ensure_root_domain()?;
        let raw_image = self.open_image_from_data(raw_assembly)?;

        self.attach = true;
        let assembly = self.open_assembly_from_image(raw_image)?;
        self.invoke_assembly_method(assembly, namespace, class_name, method_name)?;

        Ok(assembly)
    }

    pub fn eject(
        &mut self,
        assembly: NonZeroUsize,
        namespace: &str,
        class_name: &str,
        method_name: &str,
    ) -> Result<()> {
        if class_name.is_empty() {
            return Err(Error::EmptyClassName);
        }

        if method_name.is_empty() {
            return Err(Error::EmptyMethodName);
        }

        self.ensure_root_domain()?;
        self.attach = true;

        self.invoke_assembly_method(assembly, namespace, class_name, method_name)?;
        let address = self.export(Self::MONO_ASSEMBLY_CLOSE)?;
        self.execute(address, &[assembly.get()])?;

        Ok(())
    }

    fn invoke_assembly_method(
        &mut self,
        assembly: NonZeroUsize,
        namespace: &str,
        class_name: &str,
        method_name: &str,
    ) -> Result<()> {
        let image = self.get_image_from_assembly(assembly)?;
        let class = self.get_class_from_name(image, namespace, class_name)?;
        let method = self.get_method_from_name(class, method_name)?;
        self.runtime_invoke(method)
    }

    fn ensure_root_domain(&mut self) -> Result<()> {
        if self.root_domain.is_some() {
            return Ok(());
        }

        let address = self.export(Self::MONO_GET_ROOT_DOMAIN)?;
        let root_domain = self.execute(address, &[])?;
        self.root_domain = Some(
            NonZeroUsize::new(root_domain).ok_or(Error::NullReturn(Self::MONO_GET_ROOT_DOMAIN))?,
        );
        Ok(())
    }

    fn open_image_from_data(&mut self, assembly: &[u8]) -> Result<NonZeroUsize> {
        //allocate space for pointer
        let status_ptr = self.memory.allocate_and_write(&0i32.to_le_bytes())?;

        let assembly_data_ptr = self.memory.allocate_and_write(assembly)?;

        //fetch
        let mono_image_open_from_data_address = self.export(Self::MONO_IMAGE_OPEN_FROM_DATA)?;

        //execute with pre alloc
        let raw_image = self.execute(
            mono_image_open_from_data_address,
            &[assembly_data_ptr.get(), assembly.len(), 1, status_ptr.get()],
        )?;

        self.check_image_status(status_ptr, Self::MONO_IMAGE_OPEN_FROM_DATA)?;

        NonZeroUsize::new(raw_image).ok_or(Error::NullReturn(Self::MONO_IMAGE_OPEN_FROM_DATA))
    }

    fn open_assembly_from_image(&mut self, image: NonZeroUsize) -> Result<NonZeroUsize> {
        let status_ptr = self.memory.allocate_and_write(&0i32.to_le_bytes())?;
        let empty_array_ptr = self.memory.allocate_and_write(&[0u8])?;

        let address = self.export(Self::MONO_ASSEMBLY_LOAD_FROM_FULL)?;
        let assembly =
            self.execute(address, &[image.get(), empty_array_ptr.get(), status_ptr.get(), 0])?;

        self.check_image_status(status_ptr, Self::MONO_ASSEMBLY_LOAD_FROM_FULL)?;

        NonZeroUsize::new(assembly).ok_or(Error::NullReturn(Self::MONO_ASSEMBLY_LOAD_FROM_FULL))
    }

    fn check_image_status(
        &mut self,
        status_ptr: NonZeroUsize,
        operation: &'static str,
    ) -> Result<()> {
        let status = MonoImageOpenStatus::from(self.memory.read_int(status_ptr)?);
        if status == MonoImageOpenStatus::Ok {
            return Ok(());
        }

        let address = self.export(Self::MONO_IMAGE_STRERROR)?;
        let message_ptr = self.execute(address, &[status as usize])?;
        let message_ptr =
            NonZeroUsize::new(message_ptr).ok_or(Error::NullReturn(Self::MONO_IMAGE_STRERROR))?;
        let message = self.memory.read_string(message_ptr, 256)?;

        Err(Error::MonoOperation { operation, message })
    }

    fn get_image_from_assembly(&mut self, assembly: NonZeroUsize) -> Result<NonZeroUsize> {
        let address = self.export(Self::MONO_ASSEMBLY_GET_IMAGE)?;
        let image = self.execute(address, &[assembly.get()])?;
        NonZeroUsize::new(image).ok_or(Error::NullReturn(Self::MONO_ASSEMBLY_GET_IMAGE))
    }

    fn get_class_from_name(
        &mut self,
        image: NonZeroUsize,
        namespace: &str,
        class_name: &str,
    ) -> Result<NonZeroUsize> {
        let namespace_ptr = self.memory.allocate_and_write(namespace.as_bytes())?;
        let class_name_ptr = self.memory.allocate_and_write(class_name.as_bytes())?;

        let address = self.export(Self::MONO_CLASS_FROM_NAME)?;
        let class =
            self.execute(address, &[image.get(), namespace_ptr.get(), class_name_ptr.get()])?;
        NonZeroUsize::new(class).ok_or(Error::NullReturn(Self::MONO_CLASS_FROM_NAME))
    }

    fn get_method_from_name(
        &mut self,
        class: NonZeroUsize,
        method_name: &str,
    ) -> Result<NonZeroUsize> {
        let method_name_ptr = self.memory.allocate_and_write(method_name.as_bytes())?;

        let address = self.export(Self::MONO_CLASS_GET_METHOD_FROM_NAME)?;
        let method = self.execute(address, &[class.get(), method_name_ptr.get(), 0])?;
        NonZeroUsize::new(method).ok_or(Error::NullReturn(Self::MONO_CLASS_GET_METHOD_FROM_NAME))
    }

    fn get_class_name(&mut self, mono_object: NonZeroUsize) -> Result<String> {
        let address = self.export(Self::MONO_OBJECT_GET_CLASS)?;
        let class_address = self.execute(address, &[mono_object.get()])?;
        let class_address = NonZeroUsize::new(class_address)
            .ok_or(Error::NullReturn(Self::MONO_OBJECT_GET_CLASS))?;

        let address = self.export(Self::MONO_CLASS_GET_NAME)?;
        let class_name_address = self.execute(address, &[class_address.get()])?;
        let class_name_address = NonZeroUsize::new(class_name_address)
            .ok_or(Error::NullReturn(Self::MONO_CLASS_GET_NAME))?;

        self.memory.read_string(class_name_address, 256)
    }

    fn read_mono_string(&self, mono_string: NonZeroUsize) -> Result<String> {
        let offset = if self.is_64_bit { 0x10 } else { 0x8 };
        let len_address = checked_add(mono_string, offset)?;
        let Some(len) = NonZeroUsize::new(usize::try_from(self.memory.read_int(len_address)?)?)
        else {
            return Ok(String::new());
        };

        let offset_str = if self.is_64_bit { 0x14 } else { 0xC };
        let string_address = checked_add(mono_string, offset_str)?;
        let byte_len =
            NonZeroUsize::new(checked_mul(len.get(), 2)?).ok_or(Error::ArithmeticOverflow)?;
        let bytes = self.memory.read_bytes(string_address, byte_len)?;
        let utf16_units: Vec<u16> =
            bytes.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
        Ok(String::from_utf16(&utf16_units)?)
    }

    fn runtime_invoke(&mut self, method: NonZeroUsize) -> Result<()> {
        let exc_ptr = self.allocate_pointer()?;

        //res
        let address = self.export(Self::MONO_RUNTIME_INVOKE)?;
        self.execute(address, &[method.get(), 0, 0, exc_ptr.get()])?;

        let exc = self.memory.read_pointer(exc_ptr, self.is_64_bit)?;
        if let Some(exc) = NonZeroUsize::new(exc) {
            let class_name = self.get_class_name(exc)?;
            let message_address = checked_add(exc, if self.is_64_bit { 0x20 } else { 0x10 })?;
            let message = self.read_mono_string(message_address)?;
            return Err(Error::ManagedException { class_name, message });
        }

        Ok(())
    }

    fn allocate_pointer(&mut self) -> Result<NonZeroUsize> {
        if self.is_64_bit {
            self.memory.allocate_and_write(&0i64.to_le_bytes())
        } else {
            self.memory.allocate_and_write(&0i32.to_le_bytes())
        }
    }

    fn execute(&mut self, address: NonZeroUsize, args: &[usize]) -> Result<usize> {
        let ret_val_ptr = self.allocate_pointer()?;

        let code = if self.is_64_bit {
            self.assemble_64(address, ret_val_ptr, args)?
        } else {
            self.assemble_86(address, ret_val_ptr, args)?
        };
        let alloc = self.memory.allocate_and_write(&code)?;

        let mut thread_id: u32 = 0;
        let thread = unsafe {
            CreateRemoteThread(
                self.memory.as_handle().as_raw_handle() as HANDLE,
                std::ptr::null(),
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
                >(alloc.get())),
                std::ptr::null(),
                0,
                &mut thread_id,
            )
        };

        if thread.is_null() || thread == INVALID_HANDLE_VALUE {
            return Err(Error::Windows {
                operation: "failed to create a remote thread",
                source: std::io::Error::last_os_error(),
            });
        }

        // SAFETY: CreateRemoteThread returned a valid, owned handle.
        let thread = unsafe { OwnedHandle::from_raw_handle(thread) };

        let wait_result =
            unsafe { WaitForSingleObject(thread.as_raw_handle() as HANDLE, u32::MAX) };
        if wait_result == WAIT_FAILED {
            return Err(Error::Windows {
                operation: "failed to wait for a remote thread",
                source: std::io::Error::last_os_error(),
            });
        }

        let ret = self.memory.read_pointer(ret_val_ptr, self.is_64_bit)?;

        if ret == 0xC0000005 {
            let function_name = self
                .exports
                .iter()
                .find(|(_, export)| **export == address)
                .map(|(name, _)| *name)
                .unwrap_or("unknown function");

            return Err(Error::AccessViolation(function_name));
        }

        Ok(ret)
    }

    fn assemble_86(
        &self,
        function_ptr: NonZeroUsize,
        ret_val_ptr: NonZeroUsize,
        args: &[usize],
    ) -> Result<Vec<u8>> {
        let mut asm = Assembler::new()?;

        if let (true, Some(mono_thread_attach), Some(root_domain)) =
            (self.attach, self.exports.get(Self::MONO_THREAD_ATTACH).copied(), self.root_domain)
        {
            asm.push(root_domain.get() as isize)?;
            asm.mov_eax(mono_thread_attach.get() as isize)?;
            asm.call_eax()?;
            asm.add_esp(4)?;
        }

        for &arg in args.iter().rev() {
            asm.push(arg as isize)?;
        }

        asm.mov_eax(function_ptr.get() as isize)?;
        asm.call_eax()?;
        asm.add_esp(u8::try_from(checked_mul(args.len(), 4)?)?)?;
        asm.mov_eax_to(ret_val_ptr)?;
        asm.return_()?;

        asm.to_byte_array()
    }

    fn assemble_64(
        &self,
        function_ptr: NonZeroUsize,
        ret_val_ptr: NonZeroUsize,
        args: &[usize],
    ) -> Result<Vec<u8>> {
        let mut asm = Assembler::new()?;

        asm.sub_rsp(40)?;

        if let (true, Some(mono_thread_attach), Some(root_domain)) =
            (self.attach, self.exports.get(Self::MONO_THREAD_ATTACH).copied(), self.root_domain)
        {
            asm.mov_rax(mono_thread_attach.get())?;
            asm.mov_rcx(root_domain.get())?;
            asm.call_rax()?;
        }

        asm.mov_rax(function_ptr.get())?;

        for (i, &arg) in args.iter().enumerate() {
            match i {
                0 => asm.mov_rcx(arg)?,
                1 => asm.mov_rdx(arg)?,
                2 => asm.mov_r8(arg)?,
                3 => asm.mov_r9(arg)?,
                _ => break,
            }
        }

        asm.call_rax()?;
        asm.add_rsp(40)?;
        asm.mov_rax_to(ret_val_ptr)?;
        asm.return_()?;

        asm.to_byte_array()
    }
}
