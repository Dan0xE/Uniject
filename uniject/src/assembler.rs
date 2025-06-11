use iced_x86::code_asm::*;

use crate::injector_exceptions::InjectorException;

pub type AssemblerResult<T> = Result<T, InjectorException>;

pub struct Assembler {
    asm: CodeAssembler,
}

impl Assembler {
    pub fn new() -> AssemblerResult<Self> {
        Ok(Assembler { asm: CodeAssembler::new(64)? })
    }

    pub fn mov_rax(&mut self, arg: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(rax, arg as u64)?)
    }

    pub fn mov_rcx(&mut self, arg: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(rcx, arg as u64)?)
    }

    pub fn mov_rdx(&mut self, arg: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(rdx, arg as u64)?)
    }

    pub fn mov_r8(&mut self, arg: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(r8, arg as u64)?)
    }

    pub fn mov_r9(&mut self, arg: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(r9, arg as u64)?)
    }

    pub fn sub_rsp(&mut self, arg: u8) -> AssemblerResult<()> {
        Ok(self.asm.sub(rsp, arg as i32)?)
    }

    pub fn call_rax(&mut self) -> AssemblerResult<()> {
        Ok(self.asm.call(rax)?)
    }

    pub fn add_rsp(&mut self, arg: u8) -> AssemblerResult<()> {
        Ok(self.asm.add(rsp, arg as i32)?)
    }

    pub fn mov_rax_to(&mut self, dest: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(qword_ptr(dest as u64), rax)?)
    }

    pub fn push(&mut self, arg: isize) -> AssemblerResult<()> {
        Ok(self.asm.push(arg as i32)?)
    }

    pub fn mov_eax(&mut self, arg: isize) -> AssemblerResult<()> {
        Ok(self.asm.mov(eax, arg as i32)?)
    }

    pub fn call_eax(&mut self) -> AssemblerResult<()> {
        Ok(self.asm.call(eax)?)
    }

    pub fn add_esp(&mut self, arg: u8) -> AssemblerResult<()> {
        Ok(self.asm.add(esp, arg as i32)?)
    }

    pub fn mov_eax_to(&mut self, dest: usize) -> AssemblerResult<()> {
        Ok(self.asm.mov(dword_ptr(dest as u64), eax)?)
    }

    pub fn return_(&mut self) -> AssemblerResult<()> {
        Ok(self.asm.ret()?)
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_byte_array(&mut self) -> AssemblerResult<Vec<u8>> {
        Ok(self.asm.assemble(0)?)
    }
}
