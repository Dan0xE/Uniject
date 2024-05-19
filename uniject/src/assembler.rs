use std::collections::VecDeque;

pub struct Assembler {
    asm: VecDeque<u8>
}

impl Assembler {
    pub fn new() -> Self {
        Assembler {
            asm: VecDeque::new()
        }
    }

    pub fn mov_rax(&mut self, arg: usize) {
        self.asm.extend([0x48, 0xB8]);
        self.asm.extend(arg.to_le_bytes());
    }

    pub fn mov_rcx(&mut self, arg: usize) {
        self.asm.extend([0x48, 0xB9]);
        self.asm.extend(arg.to_le_bytes());
    }

    pub fn mov_rdx(&mut self, arg: usize) {
        self.asm.extend([0x48, 0xBA]);
        self.asm.extend(arg.to_le_bytes());
    }

    pub fn mov_r8(&mut self, arg: usize) {
        self.asm.extend([0x49, 0xB8]);
        self.asm.extend(arg.to_le_bytes());
    }

    pub fn mov_r9(&mut self, arg: usize) {
        self.asm.extend([0x49, 0xB9]);
        self.asm.extend(arg.to_le_bytes());
    }

    pub fn sub_rsp(&mut self, arg: u8) {
        self.asm.extend([0x48, 0x83, 0xEC]);
        self.asm.push_back(arg);
    }

    pub fn call_rax(&mut self) {
        self.asm.extend([0xFF, 0xD0]);
    }

    pub fn add_rsp(&mut self, arg: u8) {
        self.asm.extend([0x48, 0x83, 0xC4]);
        self.asm.push_back(arg);
    }

    pub fn mov_rax_to(&mut self, dest: usize) {
        self.asm.extend([0x48, 0xA3]);
        self.asm.extend(dest.to_le_bytes());
    }

    pub fn push(&mut self, arg: isize) {
        if arg >= -128 && arg <= 127 {
            self.asm.push_back(0x6A);
            self.asm.push_back(arg as u8);
        } else {
            self.asm.push_back(0x68);
            self.asm.extend((arg as i32).to_le_bytes());
        }
    }

    pub fn mov_eax(&mut self, arg: isize) {
        self.asm.push_back(0xB8);
        self.asm.extend((arg as i32).to_le_bytes());
    }

    pub fn call_eax(&mut self) {
        self.asm.extend([0xFF, 0xD0]);
    }

    pub fn add_esp(&mut self, arg: u8) {
        self.asm.extend([0x83, 0xC4]);
        self.asm.push_back(arg);
    }

    pub fn mov_eax_to(&mut self, dest: usize) {
        self.asm.push_back(0xA3);
        self.asm.extend((dest as i32).to_le_bytes());
    }

    pub fn return_(&mut self) {
        self.asm.push_back(0xC3);
    }

    pub fn to_byte_array(&self) -> Vec<u8> {
        self.asm.iter().cloned().collect()
    }

    
    // pub fn get_asm(&self) -> Vec<u8> {
    //     self.asm.iter().cloned().collect()
    // }

    // pub fn clear(&mut self) {
    //     self.asm.clear();
    // }
}
