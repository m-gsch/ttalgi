use ansi_term::Colour::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use keystone::{Arch, AsmResult, Keystone};
use std::io::{self, Write};
use std::iter;
use std::process;
use unicorn::{Cpu, CpuX86};

const START_ADDRESS: u64 = 0x1000;
const STACK_ADDRESS: u64 = 0x2000;
const BIT_SIZE: usize = 4;

//[TODO] Comment code
//[TODO] Implement Unicorn and Keystone functions as part of Ttalgi
//[TODO] Fix update_disasm so it doesn't need params
//[TODO] Add addresses to print_disasm
//[TODO] Keystone and Unicorn as struct tuple Engine in Ttalgi
//[TODO] Constants should be part of Ttalgi and not be constant,they are set at initialization
//[TODO] Implement return Result in main and get rid of all those unwraps
//[TODO] Implement clear screen [Ctrl + L]
struct Ttalgi {
    engine: Keystone,
    emu: unicorn::CpuX86,
    regs: Vec<Register>,
    asm_code: Vec<Disassembly>,
}

struct Register {
    uc_reg: unicorn::RegisterX86,
    text: String,
    content: u64,
    changed: bool,
}

struct Disassembly {
    text: String,
    asm_res: AsmResult,
}

enum TtalgiArch {
    X86,
    X86_64,
}

#[derive(Debug)]
enum TtalgiError {
    KeystoneError(keystone::Error),
    UnicornError(unicorn::Error),
}

impl From<keystone::Error> for TtalgiError {
    fn from(error: keystone::Error) -> Self {
        TtalgiError::KeystoneError(error)
    }
}

impl From<unicorn::Error> for TtalgiError {
    fn from(error: unicorn::Error) -> Self {
        TtalgiError::UnicornError(error)
    }
}
impl Ttalgi {
    fn new(arch: TtalgiArch) -> Result<Ttalgi, TtalgiError> {
        let engine = match arch {
            TtalgiArch::X86 => Keystone::new(Arch::X86, keystone::Mode::MODE_32)?,
            TtalgiArch::X86_64 => Keystone::new(Arch::X86, keystone::Mode::MODE_64)?,
        };
        // Setting Syntax breaks asm, interprets all numbers as hex (mov eax,16 == mov eax,0x16)
        //engine.option(OptionType::SYNTAX, OptionValue::SYNTAX_INTEL)?;

        let emu = match arch {
            TtalgiArch::X86 => CpuX86::new(unicorn::Mode::MODE_32)?,
            TtalgiArch::X86_64 => CpuX86::new(unicorn::Mode::MODE_64)?,
        };
        emu.mem_map(START_ADDRESS, 0x1000, unicorn::Protection::ALL)?;
        emu.reg_write(unicorn::RegisterX86::ESP, STACK_ADDRESS)?;
        emu.reg_write(unicorn::RegisterX86::EBP, STACK_ADDRESS)?;
        emu.reg_write(unicorn::RegisterX86::EIP, START_ADDRESS)?;

        let mut regs = Vec::new();
        match arch {
            TtalgiArch::X86 => {
                let eax = Register {
                    uc_reg: unicorn::RegisterX86::EAX,
                    text: "EAX".to_string(),
                    content: 0,
                    changed: false,
                };
                let ebx = Register {
                    uc_reg: unicorn::RegisterX86::EBX,
                    text: "EBX".to_string(),
                    ..eax
                };
                let ecx = Register {
                    uc_reg: unicorn::RegisterX86::ECX,
                    text: "ECX".to_string(),
                    ..eax
                };
                let edx = Register {
                    uc_reg: unicorn::RegisterX86::EDX,
                    text: "EDX".to_string(),
                    ..eax
                };
                let edi = Register {
                    uc_reg: unicorn::RegisterX86::EDI,
                    text: "EDI".to_string(),
                    ..eax
                };
                let esi = Register {
                    uc_reg: unicorn::RegisterX86::ESI,
                    text: "ESI".to_string(),
                    ..eax
                };
                let ebp = Register {
                    uc_reg: unicorn::RegisterX86::EBP,
                    text: "EBP".to_string(),
                    ..eax
                };
                let esp = Register {
                    uc_reg: unicorn::RegisterX86::ESP,
                    text: "ESP".to_string(),
                    ..eax
                };
                let eip = Register {
                    uc_reg: unicorn::RegisterX86::EIP,
                    text: "EIP".to_string(),
                    ..eax
                };
                regs.push(eax);
                regs.push(ebx);
                regs.push(ecx);
                regs.push(edx);
                regs.push(edi);
                regs.push(esi);
                regs.push(ebp);
                regs.push(esp);
                regs.push(eip);
            }
            TtalgiArch::X86_64 => (),
        }
        let asm_code = Vec::new();
        Ok(Ttalgi {
            engine,
            emu,
            regs,
            asm_code,
        })
    }

    fn update_regs(&mut self) -> Result<(), TtalgiError> {
        for r in &mut self.regs {
            let value = self.emu.reg_read(r.uc_reg)?;
            r.changed = if value != r.content { true } else { false };
            r.content = value;
        }
        Ok(())
    }

    fn update_disasm(&mut self, text: String, asm_res: AsmResult) {
        self.asm_code.push(Disassembly { text, asm_res });
    }

    fn print_regs(&self) {
        println!("{}", Blue.paint("─────────[ REGISTERS ]────────"));
        for r in &self.regs {
            let r_content = if r.changed {
                Red.paint(format!("{:#x}", r.content)).to_string()
            } else {
                format!("{:#x}", r.content)
            };
            println!("{}\t{}", Style::new().bold().paint(&r.text), r_content);
        }
    }

    fn print_stack(&self) -> Result<(), TtalgiError> {
        let esp = self.emu.reg_read(unicorn::RegisterX86::ESP)?;
        let ebp = self.emu.reg_read(unicorn::RegisterX86::EBP)?;
        let offset = ebp - esp;
        if offset > 0 {
            let mut bytes: [u8; BIT_SIZE] = [0; BIT_SIZE];
            println!("{}", Blue.paint("─────────[ STACK ]────────────"));
            for n in (0..offset).step_by(BIT_SIZE) {
                self.emu.mem_read(esp + n, &mut bytes[..])?;
                let stack_addr = format!("{:#x}", esp + n);
                let stack_val = format!("{:#x}", u32::from_le_bytes(bytes));
                println!("{}\t{}", Yellow.paint(stack_addr), stack_val);
            }
        }
        Ok(())
    }

    fn print_disasm(&self) {
        if !self.asm_code.is_empty() {
            println!("{}", Blue.paint("─────────[ DISASM ]───────────"));
        }
        for disasm in &self.asm_code {
            let mut hex_string = String::new();
            for i in 0..(disasm.asm_res.size as usize) {
                hex_string.push_str(&format!("{:x}", disasm.asm_res.bytes[i]));
            }
            let spaces = iter::repeat(" ")
                .take(20 - hex_string.len())
                .collect::<String>();
            println!("{}{}{}", hex_string, spaces, disasm.text);
        }
    }
}

fn main() {
    let mut repl = Ttalgi::new(TtalgiArch::X86).unwrap();
    let mut eip = START_ADDRESS;
    loop {
        repl.update_regs().unwrap();
        repl.print_regs();
        repl.print_stack().unwrap();
        repl.print_disasm();

        print!("{}", Green.bold().paint("x86> "));
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => {
                println!("quit");
                process::exit(0);
            }
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
        .unwrap();
        let asm_text = input.trim().to_string();
        let bytecode = match repl.engine.asm(input, eip) {
            Err(_) => {
                println!("Could not assemble instruction.");
                continue;
            }
            Ok(asm) => asm,
        };

        repl.emu.mem_write(eip, &bytecode.bytes).unwrap();

        repl.emu
            .emu_start(eip, eip + bytecode.size as u64, 0, 1)
            .unwrap();

        eip = repl.emu.reg_read(unicorn::RegisterX86::EIP).unwrap();
        repl.update_disasm(asm_text, bytecode);
    }
}
