use std::{collections::HashMap, ptr::null_mut};

use std::sync::LazyLock;
use winapi::{ctypes::c_void, shared::{minwindef::DWORD, ntdef::HANDLE}};

use crate::{assembler::Assembler, injector_exceptions::InjectorException, memory::Memory, native::{CloseHandle, CreateRemoteThread, OpenProcess, WaitForSingleObject, WaitResult, ProcessAccessRights}, proc_utils::{find_process_id_by_name, get_exported_functions, get_mono_module, is_64_bit_process}, status::MonoImageOpenStatus};

static EXPORTS: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    HashMap::from([
        ("mono_get_root_domain", 0),
        ("mono_thread_attach", 0),
        ("mono_image_open_from_data", 0),
        ("mono_assembly_load_from_full", 0),
        ("mono_assembly_get_image", 0),
        ("mono_class_from_name", 0),
        ("mono_class_get_method_from_name", 0),
        ("mono_runtime_invoke", 0),
        ("mono_assembly_close", 0),
        ("mono_image_strerror", 0),
        ("mono_object_get_class", 0),
        ("mono_class_get_name", 0),
    ])
});


pub struct Injector {
    handle: HANDLE,
    memory: Memory,
    exports: HashMap<&'static str, usize>,
    root_domain: usize,
    attach: bool,
    mono_module: usize,
    pub is_64_bit: bool,
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

    pub fn new_by_name(process_name: &str) -> Result<Self, InjectorException> {
        let process_id = find_process_id_by_name(process_name)
            .ok_or_else(|| InjectorException::new(&format!("Could not find a process with the name {}", process_name)))?;

        Self::new(process_id)
    }

    pub fn new(process_id: u32) -> Result<Self, InjectorException> {
        let handle = unsafe { OpenProcess(ProcessAccessRights::ProcessAllAccess as u32 , 0, process_id) };
        if handle == null_mut() {
            return Err(InjectorException::new(&format!("Failed to open process with ID {}", process_id)));
        }

        let mono_module = match get_mono_module(handle)? {
            Some(module) => module,
            None => return Err(InjectorException::new("Mono module not found")),
        };

        let is_64_bit = is_64_bit_process(handle)?;

        let memory = Memory::new(handle).map_err(|err| InjectorException::with_inner("Failed to create memory handler", Box::new(err)))?;

        Ok(Injector {
            handle,
            memory,
            exports: EXPORTS.clone(),
            root_domain: 0,
            attach: false,
            mono_module,
            is_64_bit,
        })
    }

    pub fn new_with_handle(
        process_handle: HANDLE,
        mono_module: usize,
    ) -> Result<Self, InjectorException> {
        if process_handle == null_mut() {
            return Err(InjectorException::new("Argument cannot be zero (processHandle)"));
        }

        if mono_module == 0 {
            return Err(InjectorException::new("Argument cannot be zero (monoModule)"));
        }

        let is_64_bit = is_64_bit_process(process_handle)?;

        let memory = Memory::new(process_handle).map_err(|err| InjectorException::with_inner(
            "Failed to create memory handler",
            Box::new(err),
        ))?;

        Ok(Injector {
            handle: process_handle,
            memory,
            exports : EXPORTS.clone(),
            root_domain: 0,
            attach: false,
            mono_module,
            is_64_bit,
        })
    }

    pub fn dispose(&mut self) {
        // self.memory.clear_allocations(); //drop should be enough
        unsafe {
            CloseHandle(self.handle);
        }
    }

    pub fn obtain_mono_exports(&mut self) -> Result<(), InjectorException> {
        let exported_functions = get_exported_functions(self.handle, self.mono_module)?;

        for ef in exported_functions {
            if let Some(export) = self.exports.get_mut(&*ef.name) {
                *export = ef.address;
            }
        }

        for (name, &address) in &self.exports {
            if address == 0 {
                return Err(InjectorException::new(&format!(
                    "Failed to obtain the address of {}()",
                    name
                )));
            }
        }

        Ok(())
    }

    pub fn inject(
        &mut self,
        raw_assembly: &[u8],
        namespace: &str,
        class_name: &str,
        method_name: &str,
    ) -> Result<usize, InjectorException> {
        if raw_assembly.is_empty() {
            return Err(InjectorException::new("rawAssembly cannot be empty"));
        }

        if class_name.is_empty() {
            return Err(InjectorException::new("className cannot be null"));
        }

        if method_name.is_empty() {
            return Err(InjectorException::new("methodName cannot be null"));
        }

        self.obtain_mono_exports()?;

        self.root_domain = self.get_root_domain()?;
        let raw_image = self.open_image_from_data(raw_assembly)?;

        self.attach = true;
        let assembly = self.open_assembly_from_image(raw_image)?;
        let image = self.get_image_from_assembly(assembly)?;
        let class = self.get_class_from_name(image, namespace, class_name)?;
        let method = self.get_method_from_name(class, method_name)?;

        self.runtime_invoke(method)?;

        Ok(assembly)
    }

    pub fn eject(
        &mut self,
        assembly: usize,
        namespace: &str,
        class_name: &str,
        method_name: &str,
    ) -> Result<(), InjectorException> {
        if assembly == 0 {
            return Err(InjectorException::new("Assembly cannot be zero"));
        }

        if class_name.is_empty() {
            return Err(InjectorException::new("Class name cannot be null"));
        }

        if method_name.is_empty() {
            return Err(InjectorException::new("Method name cannot be null"));
        }

        self.obtain_mono_exports()?;
        self.root_domain = self.get_root_domain()?;
        self.attach = true;

        let image = self.get_image_from_assembly(assembly)?;
        let class = self.get_class_from_name(image, namespace, class_name)?;
        let method = self.get_method_from_name(class, method_name)?;

        self.runtime_invoke(method)?;
        self.close_assembly(assembly)?;

        Ok(())
    }

    fn throw_if_null(&self, ptr: usize, method_name: &str) -> Result<(), InjectorException> {
        if ptr == 0 {
            return Err(InjectorException::new(&format!(
                "{}() returned NULL",
                method_name
            )));
        }

        Ok(())
    }

    pub fn get_root_domain(&mut self) -> Result<usize, InjectorException> {
        let root_domain = self.execute(
            *self
                .exports
                .get(Self::MONO_GET_ROOT_DOMAIN)
                .ok_or_else(|| InjectorException::new("Mono get root domain export not found"))?,
            &[],
        )?;
        self.throw_if_null(root_domain, Self::MONO_GET_ROOT_DOMAIN)?;

        Ok(root_domain)
    }

    pub fn open_image_from_data(&mut self, assembly: &[u8]) -> Result<usize, InjectorException> {
        //allocate space for pointer
        let status_ptr = self.memory.allocate(4)?;

        let assembly_data_ptr = self.memory.allocate_and_write(assembly)?;

        //fetch
        let mono_image_open_from_data_address = *self
            .exports
            .get(Self::MONO_IMAGE_OPEN_FROM_DATA)
            .ok_or_else(|| InjectorException::new("Mono image open from data export not found"))?;

        //execute with pre alloc
        let raw_image = self.execute(
            mono_image_open_from_data_address,
            &[assembly_data_ptr, assembly.len() as usize, 1, status_ptr],
        )?;

        //read status
        let status = MonoImageOpenStatus::from(self.memory.read_int(status_ptr)?);

        if status != MonoImageOpenStatus::MonoImageOk {
            //get error msg ptr
            let mono_image_strerror_address = *self
                .exports
                .get(Self::MONO_IMAGE_STRERROR)
                .ok_or_else(|| InjectorException::new("Mono image strerror export not found"))?;
            let message_ptr = self.execute(mono_image_strerror_address, &[status as usize])?;

            //read msg
            let message = self.memory.read_string(message_ptr, 256)?;
            return Err(InjectorException::new(&format!(
                "{}() failed: {}",
                Self::MONO_IMAGE_OPEN_FROM_DATA, message
            )));
        }

        Ok(raw_image)
    }

    pub fn open_assembly_from_image(&mut self, image: usize) -> Result<usize, InjectorException> {
        let status_ptr = self.memory.allocate(4)?;
        let empty_array_ptr = self.memory.allocate_and_write(&[0u8])?;

        let assembly = self.execute(
            *self
                .exports
                .get(Self::MONO_ASSEMBLY_LOAD_FROM_FULL)
                .ok_or_else(|| InjectorException::new("Mono assembly load from full export not found"))?,
            &[image, empty_array_ptr, status_ptr, 0],
        )?;

        let status = MonoImageOpenStatus::from(self.memory.read_int(status_ptr)?);

        if status != MonoImageOpenStatus::MonoImageOk {
            let message_ptr = self.execute(
                *self
                    .exports
                    .get(Self::MONO_IMAGE_STRERROR)
                    .ok_or_else(|| InjectorException::new("Mono image strerror export not found"))?,
                &[status as usize],
            )?;

            let message = self.memory.read_string(message_ptr, 256)?;
            return Err(InjectorException::new(&format!(
                "{}() failed: {}",
                Self::MONO_ASSEMBLY_LOAD_FROM_FULL, message
            )));
        }

        Ok(assembly)
    }

    pub fn get_image_from_assembly(&mut self, assembly: usize) -> Result<usize, InjectorException> {
        let image = self.execute(
            *self
                .exports
                .get(Self::MONO_ASSEMBLY_GET_IMAGE)
                .ok_or_else(|| InjectorException::new("Mono assembly get image export not found"))?,
            &[assembly],
        )?;
        self.throw_if_null(image, Self::MONO_ASSEMBLY_GET_IMAGE)?;

        Ok(image)
    }

    pub fn get_class_from_name(
        &mut self,
        image: usize,
        namespace: &str,
        class_name: &str,
    ) -> Result<usize, InjectorException> {
        let namespace_ptr = self.memory.allocate_and_write(namespace.as_bytes())?;
        let class_name_ptr = self.memory.allocate_and_write(class_name.as_bytes())?;

        let class = self.execute(
            *self
                .exports
                .get(Self::MONO_CLASS_FROM_NAME)
                .ok_or_else(|| InjectorException::new("Mono class from name export not found"))?,
            &[image, namespace_ptr, class_name_ptr],
        )?;
        self.throw_if_null(class, Self::MONO_CLASS_FROM_NAME)?;

        Ok(class)
    }

    pub fn get_method_from_name(
        &mut self,
        class: usize,
        method_name: &str,
    ) -> Result<usize, InjectorException> {
        let method_name_ptr = self.memory.allocate_and_write(method_name.as_bytes())?;

        let method = self.execute(
            *self
                .exports
                .get(Self::MONO_CLASS_GET_METHOD_FROM_NAME)
                .ok_or_else(|| InjectorException::new("Mono class get method from name export not found"))?,
            &[class, method_name_ptr, 0],
        )?;
        self.throw_if_null(method, Self::MONO_CLASS_GET_METHOD_FROM_NAME)?;

        Ok(method)
    }

    pub fn get_class_name(&mut self, mono_object: usize) -> Result<String, InjectorException> {
        let class_address = self.execute(
            *self
                .exports
                .get(Self::MONO_OBJECT_GET_CLASS)
                .ok_or_else(|| InjectorException::new("Mono object get class export not found"))?,
            &[mono_object],
        )?;
        self.throw_if_null(class_address, Self::MONO_OBJECT_GET_CLASS)?;

        let class_name_address = self.execute(
            *self
                .exports
                .get(Self::MONO_CLASS_GET_NAME)
                .ok_or_else(|| InjectorException::new("Mono class get name export not found"))?,
            &[class_address],
        )?;
        self.throw_if_null(class_name_address, Self::MONO_CLASS_GET_NAME)?;

        Ok(self.memory.read_string(class_name_address, 256)?)
    }

    pub fn read_mono_string(&self, mono_string: usize) -> Result<String, InjectorException> {
        let offset = if self.is_64_bit { 0x10 } else { 0x8 };
        let len = self.memory.read_int(mono_string + offset)? as usize;

        let offset_str = if self.is_64_bit { 0x14 } else { 0xC };
        self.memory.read_unicode_string(mono_string + offset_str, len * 2)
    }

    pub fn runtime_invoke(&mut self, method: usize) -> Result<(), InjectorException> {
        let exc_ptr = if self.is_64_bit {
            self.memory.allocate_and_write_long(0)?
        } else {
            self.memory.allocate_and_write_int(0)?
        };

        //res
        self.execute(
            *self
                .exports
                .get(Self::MONO_RUNTIME_INVOKE)
                .ok_or_else(|| InjectorException::new("Mono runtime invoke export not found"))?,
            &[method, 0, 0, exc_ptr],
        )?;

        let exc = self.memory.read_int(exc_ptr)? as usize;
        if exc != 0 {
            let class_name = self.get_class_name(exc)?;
            let message = self.read_mono_string(if self.is_64_bit {
                exc + 0x20
            } else {
                exc + 0x10
            })?;
            return Err(InjectorException::new(&format!(
                "The managed method threw an exception: ({}) {}",
                class_name, message
            )));
        }

        Ok(())
    }


    pub fn close_assembly(&mut self, assembly: usize) -> Result<(), InjectorException> {
        let address = self
            .exports
            .get(Self::MONO_ASSEMBLY_CLOSE)
            .ok_or_else(|| InjectorException::new("Mono assembly close export not found"))?;

        let result = self.execute(*address, &[assembly])?;
        self.throw_if_null(result, Self::MONO_ASSEMBLY_CLOSE)?;

        Ok(())
    }

    pub fn execute(&mut self, address: usize, args: &[usize]) -> Result<usize, InjectorException> {
        let ret_val_ptr = if self.is_64_bit {
            self.memory.allocate_and_write_long(0)?
        } else {
            self.memory.allocate_and_write_int(0)?
        };

        let code = self.assemble(address, ret_val_ptr, args);
        let alloc = self.memory.allocate_and_write(&code)?;

        let mut thread_id: DWORD = 0;
        let thread: HANDLE = unsafe {
            CreateRemoteThread(
                self.handle,
                null_mut(),
                0,
                alloc as *mut c_void,
                null_mut(),
                0,
                &mut thread_id,
            )
        };

        if thread == null_mut() {
            return Err(InjectorException::new("Failed to create a remote thread"));
        }

        let wait_result = unsafe { WaitForSingleObject(thread, u32::MAX) };
        if wait_result == WaitResult::WaitFailed as DWORD {
            return Err(InjectorException::new("Failed to wait for a remote thread"));
        }

        let ret = if self.is_64_bit {
            self.memory.read_long(ret_val_ptr)? as usize
        } else {
            self.memory.read_int(ret_val_ptr)? as usize
        };

        if ret == 0xC0000005 {
            let function_name = self
                .exports
                .iter()
                .find(|(_, addr)| **addr == address)
                .map(|(name, _)| *name)
                .unwrap_or("unknown function");

            return Err(InjectorException::new(&format!(
                "An access violation occurred while executing {}()",
                function_name
            )));
        }

        Ok(ret)
    }

    pub fn assemble(&self, function_ptr: usize, ret_val_ptr: usize, args: &[usize]) -> Vec<u8> {
        if self.is_64_bit {
            self.assemble_64(function_ptr, ret_val_ptr, args)
        } else {
            self.assemble_86(function_ptr, ret_val_ptr, args)
        }
    }

    pub fn assemble_86(&self, function_ptr: usize, ret_val_ptr: usize, args: &[usize]) -> Vec<u8> {
        let mut asm = Assembler::new();

        if self.attach {
            if let Some(&mono_thread_attach) = self.exports.get(Self::MONO_THREAD_ATTACH) {
                asm.push(self.root_domain as isize);
                asm.mov_eax(mono_thread_attach as isize);
                asm.call_eax();
                asm.add_esp(4);
            }
        }

        for &arg in args.iter().rev() {
            asm.push(arg as isize);
        }

        asm.mov_eax(function_ptr as isize);
        asm.call_eax();
        asm.add_esp((args.len() * 4) as u8);
        asm.mov_eax_to(ret_val_ptr as usize);
        asm.return_();

        asm.to_byte_array()
    }

    pub fn assemble_64(&self, function_ptr: usize, ret_val_ptr: usize, args: &[usize]) -> Vec<u8> {
        let mut asm = Assembler::new();

        asm.sub_rsp(40);

        if self.attach {
            if let Some(&mono_thread_attach) = self.exports.get(Self::MONO_THREAD_ATTACH) {
                asm.mov_rax(mono_thread_attach);
                asm.mov_rcx(self.root_domain);
                asm.call_rax();
            }
        }

        asm.mov_rax(function_ptr);

        for (i, &arg) in args.iter().enumerate() {
            match i {
                0 => asm.mov_rcx(arg),
                1 => asm.mov_rdx(arg),
                2 => asm.mov_r8(arg),
                3 => asm.mov_r9(arg),
                _ => break,
            }
        }

        asm.call_rax();
        asm.add_rsp(40);
        asm.mov_rax_to(ret_val_ptr);
        asm.return_();

        asm.to_byte_array()
    }


}