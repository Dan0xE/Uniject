use std::num::NonZeroUsize;

use iced_x86::code_asm::*;

use crate::error::Result;

pub(crate) struct Assembler {
    asm: CodeAssembler,
}

impl Assembler {
    pub(crate) fn new() -> Result<Self> {
        Ok(Assembler { asm: CodeAssembler::new(64)? })
    }

    pub(crate) fn mov_rax(&mut self, arg: usize) -> Result<()> {
        Ok(self.asm.mov(rax, arg as u64)?)
    }

    pub(crate) fn mov_rcx(&mut self, arg: usize) -> Result<()> {
        Ok(self.asm.mov(rcx, arg as u64)?)
    }

    pub(crate) fn mov_rdx(&mut self, arg: usize) -> Result<()> {
        Ok(self.asm.mov(rdx, arg as u64)?)
    }

    pub(crate) fn mov_r8(&mut self, arg: usize) -> Result<()> {
        Ok(self.asm.mov(r8, arg as u64)?)
    }

    pub(crate) fn mov_r9(&mut self, arg: usize) -> Result<()> {
        Ok(self.asm.mov(r9, arg as u64)?)
    }

    pub(crate) fn sub_rsp(&mut self, arg: u8) -> Result<()> {
        Ok(self.asm.sub(rsp, arg as i32)?)
    }

    pub(crate) fn call_rax(&mut self) -> Result<()> {
        Ok(self.asm.call(rax)?)
    }

    pub(crate) fn add_rsp(&mut self, arg: u8) -> Result<()> {
        Ok(self.asm.add(rsp, arg as i32)?)
    }

    pub(crate) fn mov_rax_to(&mut self, dest: NonZeroUsize) -> Result<()> {
        Ok(self.asm.mov(qword_ptr(dest.get() as u64), rax)?)
    }

    pub(crate) fn push(&mut self, arg: isize) -> Result<()> {
        Ok(self.asm.push(arg as i32)?)
    }

    pub(crate) fn mov_eax(&mut self, arg: isize) -> Result<()> {
        Ok(self.asm.mov(eax, arg as i32)?)
    }

    pub(crate) fn call_eax(&mut self) -> Result<()> {
        Ok(self.asm.call(eax)?)
    }

    pub(crate) fn add_esp(&mut self, arg: u8) -> Result<()> {
        Ok(self.asm.add(esp, arg as i32)?)
    }

    pub(crate) fn mov_eax_to(&mut self, dest: NonZeroUsize) -> Result<()> {
        Ok(self.asm.mov(dword_ptr(dest.get() as u64), eax)?)
    }

    pub(crate) fn return_(&mut self) -> Result<()> {
        Ok(self.asm.ret()?)
    }

    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_byte_array(&mut self) -> Result<Vec<u8>> {
        Ok(self.asm.assemble(0)?)
    }
}
