use ttalgi::Repl;
use ttalgi::ReplArch;

//[TODO] Comment code
//[TODO] Implement Unicorn and Keystone functions as part of Ttalgi
//[TODO] Fix update_disasm so it doesn't need params
//[TODO] Add addresses to print_disasm
//[TODO] Keystone and Unicorn as struct tuple Engine in Ttalgi
//[TODO] Constants should be part of Ttalgi and not be constant,they are set at initialization
//[TODO] Error handling can be improved.
//[TODO] Implement clear screen [Ctrl + L]

fn main() -> Result<(), ttalgi::TtalgiError> {
    let repl = Repl::new(ReplArch::X86)?;

    ttalgi::run(repl)?;

    Ok(())
}
