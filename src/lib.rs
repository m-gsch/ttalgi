use console::style;
use keystone_engine;
use std::cell::RefCell;
use std::fmt;
use std::ops::Deref;
use std::rc::Rc;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use unicorn_engine::{RegisterX86, Unicorn, SECOND_SCALE};

#[derive(clap::ValueEnum, Clone)]
pub enum ArchEnum {
    X86,
    X64,
}

#[derive(Debug, Clone)]
struct Register(RegisterX86);

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

pub struct TtalgiContext<'a, D> {
    pub arch: ArchEnum,
    pub prompt: &'a str,
    assembler: Rc<keystone_engine::Keystone>,
    emulator: Rc<RefCell<Unicorn<'a, D>>>,
    regs: Vec<Register>,
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
                    keystone_engine::Keystone::new(
                        keystone_engine::Arch::X86,
                        keystone_engine::Mode::MODE_32,
                    )
                    .unwrap(),
                ),
                emulator: Rc::new(RefCell::new(
                    unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_32).unwrap(),
                )),
                regs: vec![
                    Register(RegisterX86::EAX),
                    Register(RegisterX86::EBX),
                    Register(RegisterX86::ECX),
                    Register(RegisterX86::EDX),
                    Register(RegisterX86::EDI),
                    Register(RegisterX86::ESI),
                    Register(RegisterX86::EBP),
                    Register(RegisterX86::ESP),
                    Register(RegisterX86::EIP),
                    Register(RegisterX86::EFLAGS),
                ],
                memory_size: 0,
                stack_start: 0,
                instruction_start: 0,
            }),
            ArchEnum::X64 => Ok(TtalgiContext {
                arch: architecture,
                prompt: "x64>",
                assembler: Rc::new(
                    keystone_engine::Keystone::new(
                        keystone_engine::Arch::X86,
                        keystone_engine::Mode::MODE_64,
                    )
                    .unwrap(),
                ),
                emulator: Rc::new(RefCell::new(
                    unicorn_engine::Unicorn::new(Arch::X86, Mode::MODE_64).unwrap(),
                )),
                regs: vec![
                    Register(RegisterX86::RAX),
                    Register(RegisterX86::RBX),
                    Register(RegisterX86::RCX),
                    Register(RegisterX86::RDX),
                    Register(RegisterX86::RDI),
                    Register(RegisterX86::RSI),
                    Register(RegisterX86::RBP),
                    Register(RegisterX86::RSP),
                    Register(RegisterX86::RIP),
                    Register(RegisterX86::RFLAGS),
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
        println!("{}", style("[REGISTERS]").cyan());
        for reg in self.regs.clone().into_iter() {
            match self.arch {
                ArchEnum::X86 => println!(
                    "{}:\t{:#010x}",
                    style(&reg).bold(),
                    self.emulator.borrow().reg_read(reg.0).unwrap()
                ),
                ArchEnum::X64 => println!(
                    "{}:\t{:#018x}",
                    style(&reg).bold(),
                    self.emulator.borrow().reg_read(reg.0).unwrap()
                ),
            };
        }
        println!("");
    }

    pub fn print_stack(&self) {
        let emu = self.emulator.borrow();

        let stack_pointer = match self.arch {
            ArchEnum::X86 => RegisterX86::ESP,
            ArchEnum::X64 => RegisterX86::RSP,
        };
        let pointer_size: usize = match self.arch {
            ArchEnum::X86 => 4,
            ArchEnum::X64 => 8,
        };

        let stack_pointer = emu.reg_read(stack_pointer).unwrap();
        let mut stack_pointer = stack_pointer & !(pointer_size - 1) as u64;
        let offset = (self.stack_start - stack_pointer) as usize;

        let mut stack_mem = vec![0; offset];
        emu.mem_read(stack_pointer, &mut stack_mem).unwrap();

        println!("{}", style("[STACK]").cyan());
        for stack_bytes in stack_mem.chunks(pointer_size) {
            match self.arch {
                ArchEnum::X86 => {
                    print!("{:#010x}", style(stack_pointer).yellow());
                    println!(
                        "\t{:#10x}",
                        u32::from_le_bytes(stack_bytes.try_into().unwrap())
                    );
                }
                ArchEnum::X64 => {
                    print!("{:#018x}", style(stack_pointer).yellow());
                    println!(
                        "\t{:#18x}",
                        u64::from_le_bytes(stack_bytes.try_into().unwrap())
                    );
                }
            }
            stack_pointer += pointer_size as u64;
        }
        println!("");
    }
}
