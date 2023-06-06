use clap::Parser;
use std::io::{self, Write};

use console::style;
use ttalgi::{ArchEnum, TtalgiContext};

//[TODO] Comment code
//[TODO] Error handling can be improved.
//[TODO] Implement clear screen [Ctrl + L]

/// Simple program that acts as an assembly REPL using Keystone and Unicorn
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// CPU Architecture of the emulator
    #[arg(short, long, value_enum, default_value_t = ArchEnum::X86)]
    architecture: ArchEnum,

    /// Size of the memory space
    #[arg(long, value_name="SIZE", value_parser=maybe_hex, default_value = "0x4000")]
    memory_size: u64,

    /// Start address of the stack
    #[arg(long, value_name="ADDRESS", value_parser=maybe_hex, default_value = "0x2000")]
    stack_start: u64,

    /// Start address of the instruction pointer
    #[arg(long, value_name="ADDRESS", value_parser=maybe_hex , default_value = "0x1000")]
    instruction_start: u64,
}

fn main() {
    let cli = Cli::parse();
    let mut ttalgi = TtalgiContext::new(cli.architecture).unwrap();

    ttalgi.init_memory(cli.memory_size, cli.stack_start, cli.instruction_start);

    loop {
        print!("{} ", style(ttalgi.prompt).green().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();

        match io::stdin().read_line(&mut input) {
            Ok(0) => {
                println!("quit");
                break;
            }
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
        .unwrap();

        ttalgi
            .execute(input)
            .unwrap_or_else(|err| eprintln!("{err}"));

        ttalgi.print_registers();
        ttalgi.print_stack();
    }
}

fn maybe_hex(s: &str) -> Result<u64, String> {
    const HEX_PREFIX: &str = "0x";
    const HEX_PREFIX_LEN: usize = HEX_PREFIX.len();

    let result = if s.to_ascii_lowercase().starts_with(HEX_PREFIX) {
        u64::from_str_radix(&s[HEX_PREFIX_LEN..], 16)
    } else {
        u64::from_str_radix(s, 10)
    };

    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(format!("{e}")),
    }
}
