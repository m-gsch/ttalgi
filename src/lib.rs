use keystone;
use std::cell::RefCell;

use std::ops::Deref;
use std::rc::Rc;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use unicorn_engine::{RegisterX86, Unicorn, SECOND_SCALE};

#[derive(clap::ValueEnum, Clone)]
pub enum ArchEnum {
    X86,
    X64,
}

pub struct TtalgiContext<'a, D> {
    pub arch: ArchEnum,
    pub prompt: &'a str,
    assembler: Rc<keystone::Keystone>,
    emulator: Rc<RefCell<Unicorn<'a, D>>>,
    regs: Vec<(&'a str, i32)>,
    pub memory_size: u64,
    pub stack_start: u64,
    pub instruction_start: u64,
}

impl TtalgiContext<'_, ()> {
    pub fn new(architecture: ArchEnum) -> Result<Self, &'static str> {
        match architecture {
            ArchEnum::X86 => Ok(TtalgiContext {
                arch: architecture,
                prompt: "x86>",
                assembler: Rc::new(
                    keystone::Keystone::new(keystone::Arch::X86, keystone::Mode::MODE_32).unwrap(),
                ),
                emulator: Rc::new(RefCell::new(
                    unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32).unwrap(),
                )),
                regs: vec![
                    ("EAX", 19),
                    ("EBX", 21),
                    ("ECX", 22),
                    ("EDX", 24),
                    ("EDI", 23),
                    ("ESI", 29),
                    ("EBP", 20),
                    ("ESP", 30),
                    ("EIP", 26),
                    ("EFLAGS", 25),
                ],
                memory_size: 0,
                stack_start: 0,
                instruction_start: 0,
            }),
            ArchEnum::X64 => Ok(TtalgiContext {
                arch: architecture,
                prompt: "x64>",
                assembler: Rc::new(
                    keystone::Keystone::new(keystone::Arch::X86, keystone::Mode::MODE_64).unwrap(),
                ),
                emulator: Rc::new(RefCell::new(
                    unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64).unwrap(),
                )),
                regs: vec![
                    ("RAX", 35),
                    ("RBX", 37),
                    ("RCX", 38),
                    ("RDX", 40),
                    ("RDI", 39),
                    ("RSI", 43),
                    ("RBP", 36),
                    ("RSP", 44),
                    ("RIP", 41),
                    ("RFLAGS", 253),
                ],
                memory_size: 0,
                stack_start: 0,
                instruction_start: 0,
            }),
        }
    }
    pub fn init_memory(&mut self, memory_size: u64, stack_start: u64, instruction_start: u64) {
        self.memory_size = memory_size;
        self.stack_start = stack_start;
        self.instruction_start = instruction_start;
        let mut emu = self.emulator.borrow_mut();
        emu.mem_map(0x0000, memory_size as usize, Permission::ALL)
            .unwrap();
        emu.reg_write(RegisterX86::ESP, stack_start).unwrap();
        emu.reg_write(RegisterX86::EBP, stack_start).unwrap();
        emu.reg_write(RegisterX86::EIP, instruction_start).unwrap();
    }

    pub fn execute(&self, instruction: String) -> Result<(), String> {
        let asm_result = match self.assembler.asm(instruction, 0) {
            Ok(asm) => Ok(asm.bytes),
            Err(e) => Err(format!("{e}")),
        }?;
        let mut emu = self.emulator.borrow_mut();
        let program_counter = emu.reg_read(RegisterX86::EIP).unwrap();
        emu.mem_write(program_counter, asm_result.deref())
            .expect("failed to write instructions");

        emu.emu_start(
            program_counter,
            program_counter + asm_result.len() as u64,
            10 * SECOND_SCALE,
            1000,
        )
        .unwrap();
        Ok(())
    }

    pub fn print_registers(&self) {
        println!("[REGISTERS]");
        for (mnemonic, reg_enum) in self.regs.clone().into_iter() {
            // [TODO] Probably change this to look more rustacean .map() or something like that
            match self.arch {
                ArchEnum::X86 => println!(
                    "{}: {:#010x}",
                    mnemonic,
                    self.emulator.borrow().reg_read(reg_enum).unwrap()
                ),
                ArchEnum::X64 => println!(
                    "{}: {:#018x}",
                    mnemonic,
                    self.emulator.borrow().reg_read(reg_enum).unwrap()
                ),
            };
        }
    }

    pub fn print_stack(&self) {
        let emu = self.emulator.borrow();

        let stack_pointer = emu.reg_read(RegisterX86::ESP).unwrap();
        let offset = self.stack_start - stack_pointer;

        let mut stack_mem = vec![0; 8];

        println!("[STACK]");
        let pointer_size = match self.arch {
            ArchEnum::X86 => 4,
            ArchEnum::X64 => 8,
        };

        for n in (0..offset).step_by(pointer_size) {
            emu.mem_read(stack_pointer + n, &mut stack_mem).unwrap();
            match self.arch {
                ArchEnum::X86 => println!(
                    "{:#010x}\t{:#10x}",
                    stack_pointer + n,
                    u32::from_le_bytes(stack_mem[..pointer_size].try_into().unwrap())
                ),
                ArchEnum::X64 => println!(
                    "{:#018x}\t{:#18x}",
                    stack_pointer + n,
                    u64::from_le_bytes(stack_mem[..pointer_size].try_into().unwrap())
                ),
            };
        }
    }
}
