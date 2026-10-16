use clap::Parser;

#[derive(Parser)]
#[command(version, about = "High-performance packet analysis tools")]
struct Cli {}

fn main() {
    Cli::parse();
}
