fn main() {
    if let Err(error) = ptbench::main_entry() {
        eprintln!("ptbench: {error}");
        std::process::exit(1);
    }
}
