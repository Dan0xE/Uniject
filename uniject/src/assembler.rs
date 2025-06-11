use iced_x86::code_asm::*;

pub struct Assembler {
    asm: CodeAssembler,
}

impl Assembler {
    pub fn new() -> Self {
        Assembler {
            asm: CodeAssembler::new(64).unwrap(),
        }
    }

    pub fn mov_rax(&mut self, arg: usize) {
        self.asm.mov(rax, arg as u64).unwrap();
    }

    pub fn mov_rcx(&mut self, arg: usize) {
        self.asm.mov(rcx, arg as u64).unwrap();
    }

    pub fn mov_rdx(&mut self, arg: usize) {
        self.asm.mov(rdx, arg as u64).unwrap();
    }

    pub fn mov_r8(&mut self, arg: usize) {
        self.asm.mov(r8, arg as u64).unwrap();
    }

    pub fn mov_r9(&mut self, arg: usize) {
        self.asm.mov(r9, arg as u64).unwrap();
    }

    pub fn sub_rsp(&mut self, arg: u8) {
        self.asm.sub(rsp, arg as i32).unwrap();
    }

    pub fn call_rax(&mut self) {
        self.asm.call(rax).unwrap();
    }

    pub fn add_rsp(&mut self, arg: u8) {
        self.asm.add(rsp, arg as i32).unwrap();
    }

    pub fn mov_rax_to(&mut self, dest: usize) {
        self.asm.mov(qword_ptr(dest as u64), rax).unwrap();
    }

    pub fn push(&mut self, arg: isize) {
        self.asm.push(arg as i32).unwrap();
    }

    pub fn mov_eax(&mut self, arg: isize) {
        self.asm.mov(eax, arg as i32).unwrap();
    }

    pub fn call_eax(&mut self) {
        self.asm.call(eax).unwrap();
    }

    pub fn add_esp(&mut self, arg: u8) {
        self.asm.add(esp, arg as i32).unwrap();
    }

    pub fn mov_eax_to(&mut self, dest: usize) {
        self.asm.mov(dword_ptr(dest as u64), eax).unwrap();
    }

    pub fn return_(&mut self) {
        self.asm.ret().unwrap();
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_byte_array(&mut self) -> Vec<u8> {
        self.asm.assemble(0).unwrap()
    }
}
