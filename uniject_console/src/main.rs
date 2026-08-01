use std::fmt::Display;
use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::exit;

use clap::{Parser, Subcommand};
use log::{error, info};
use uniject::{Injector, Result, find_process_id_by_name};

#[derive(Parser)]
#[command(name = "uniject_console")]
#[command(version = "0.1.0")]
#[command(about = "A .NET assembly injector for Mono-based games")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inject a .NET assembly into a target process
    Inject {
        /// Process ID or name of the target process
        #[arg(short, long)]
        process: String,
        /// Path to the assembly to inject
        #[arg(short, long)]
        assembly: String,
        /// Namespace containing the loader class
        #[arg(short, long)]
        namespace: String,
        /// Name of the loader class
        #[arg(short, long)]
        class: String,
        /// Name of the method to invoke
        #[arg(short, long)]
        method: String,
    },
    /// Eject a .NET assembly from a target process
    Eject {
        /// Process ID or name of the target process
        #[arg(short, long)]
        process: String,
        /// Assembly address to eject (hex format supported)
        #[arg(short, long)]
        assembly: String,
        /// Namespace containing the loader class
        #[arg(short, long)]
        namespace: String,
        /// Name of the loader class
        #[arg(short, long)]
        class: String,
        /// Name of the method to invoke
        #[arg(short, long)]
        method: String,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_default_env().filter_level(log::LevelFilter::Debug).init();
    let cli = Cli::parse();

    let process = match &cli.command {
        Commands::Inject { process, .. } | Commands::Eject { process, .. } => process,
    };
    let process_id =
        process.parse::<u32>().map_or_else(|_| find_process_id_by_name(process), Ok)?;
    let mut injector = Injector::new(process_id)?;

    match &cli.command {
        Commands::Inject { assembly, namespace, class, method, .. } => {
            inject_assembly(&mut injector, assembly, namespace, class, method);
        }
        Commands::Eject { assembly, namespace, class, method, .. } => {
            eject_assembly(&mut injector, assembly, namespace, class, method);
        }
    }

    Ok(())
}

fn inject_assembly(
    injector: &mut Injector,
    assembly_path: &str,
    namespace: &str,
    class_name: &str,
    method_name: &str,
) {
    let assembly = match fs::read(assembly_path) {
        Ok(content) => content,
        Err(_) => {
            error!("Could not read the file {}", assembly_path);
            return;
        }
    };

    match injector.inject(&assembly, namespace, class_name, method_name) {
        Ok(remote_assembly) => {
            info!(
                "{}: {}",
                Path::new(assembly_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown"),
                format_address(remote_assembly, injector.is_64_bit())
            );
        }
        Err(e) => error!("Failed to inject assembly: {}", e),
    }
}

fn eject_assembly(
    injector: &mut Injector,
    assembly_str: &str,
    namespace: &str,
    class_name: &str,
    method_name: &str,
) {
    let assembly_ptr = parse_assembly_address(assembly_str);

    match injector.eject(assembly_ptr, namespace, class_name, method_name) {
        Ok(_) => info!("Ejection successful"),
        Err(e) => error!("Ejection failed: {}", e),
    }
}

fn parse_assembly_address(addr_str: &str) -> NonZeroUsize {
    let address = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        usize::from_str_radix(&addr_str[2..], 16).unwrap_or_else(|_| {
            error!("Invalid hex address: {}", addr_str);
            exit(1);
        })
    } else {
        addr_str.parse::<usize>().unwrap_or_else(|_| {
            error!("Invalid address: {}", addr_str);
            exit(1);
        })
    };

    NonZeroUsize::new(address).unwrap_or_else(|| {
        error!("Assembly address cannot be zero");
        exit(1);
    })
}

fn format_address<T: Display + std::fmt::UpperHex>(address: T, is_64_bit: bool) -> String {
    if is_64_bit { format!("0x{:016X}", address) } else { format!("0x{:08X}", address) }
}
