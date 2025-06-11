use std::fmt::Display;
use std::fs;
use std::path::Path;
use std::process::exit;

use uniject::Injector;

mod args;
use args::CommandLineArguments;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 1 {
        print_help();
        exit(0);
    }

    let cla = CommandLineArguments::new(&args[1..]);

    let is_inject = cla.is_switch_present("inject");
    let is_eject = cla.is_switch_present("eject");

    if !is_inject && !is_eject {
        println!("No operation (inject/eject) specified");
        exit(1);
    }

    let mut injector = if let Some(pid) = cla.get_int_arg("-p") {
        match Injector::new(pid as u32) {
            Ok(injector) => injector,
            Err(err) => {
                println!("Failed to create Injector for process ID {}: {}", pid, err);
                exit(1);
            }
        }
    } else if let Some(pname) = cla.get_string_arg("-p") {
        match Injector::new_by_name(pname) {
            Ok(injector) => injector,
            Err(err) => {
                println!("Failed to create Injector for process name {}: {}", pname, err);
                exit(1);
            }
        }
    } else {
        println!("No process id/name specified");
        exit(1);
    };

    if is_inject {
        inject(&mut injector, &cla);
    } else {
        eject(&mut injector, &cla);
    }
}

fn print_help() {
    let help = r#"Uniject 0.1.0

Usage:
uniject_console <inject/eject> <options>

Options:
-p - The id or name of the target process
-a - When injecting, the path of the assembly to inject. When ejecting, the address of the assembly to eject
-n - The namespace in which the loader class resides
-c - The name of the loader class
-m - The name of the method to invoke in the loader class

Examples:
uniject_console inject -p testgame -a ExampleAssembly.dll -n ExampleAssembly -c Loader -m Load
uniject_console eject -p testgame -a 0x13D23A98 -n ExampleAssembly -c Loader -m Unload
"#;

    println!("{}", help);
}

fn inject(injector: &mut Injector, args: &CommandLineArguments) {
    let assembly_path: String;
    let namespace: String;
    let class_name: String;
    let method_name: String;

    let assembly: Vec<u8>;

    if let Some(path) = args.get_string_arg("-a") {
        match fs::read(path) {
            Ok(content) => assembly = content,
            Err(_) => {
                println!("Could not read the file {}", path);
                return;
            }
        }
        assembly_path = path.to_string();
    } else {
        println!("No assembly specified");
        return;
    }

    namespace = match args.get_string_arg("-n") {
        Some(ns) => ns.to_string(),
        None => {
            println!("No namespace specified");
            return;
        }
    };

    class_name = match args.get_string_arg("-c") {
        Some(class) => class.to_string(),
        None => {
            println!("No class name specified");
            return;
        }
    };

    method_name = match args.get_string_arg("-m") {
        Some(method) => method.to_string(),
        None => {
            println!("No method name specified");
            return;
        }
    };

    match injector.inject(&assembly, &namespace, &class_name, &method_name) {
        Ok(remote_assembly) => {
            println!(
                "{}: {}",
                Path::new(&assembly_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown"),
                format_address(remote_assembly, injector.is_64_bit)
            );
        }
        Err(e) => println!("Failed to inject assembly: {}", e),
    }
}

fn eject(injector: &mut Injector, args: &CommandLineArguments) {
    let assembly: usize;
    let namespace: String;
    let class_name: String;
    let method_name: String;

    assembly = if let Some(int_ptr) = args.get_int_arg("-a") {
        int_ptr as usize
    } else if let Some(long_ptr) = args.get_long_arg("-a") {
        long_ptr as usize
    } else {
        println!("No assembly pointer specified");
        return;
    };

    namespace = match args.get_string_arg("-n") {
        Some(ns) => ns.to_string(),
        None => {
            println!("No namespace specified");
            return;
        }
    };

    class_name = match args.get_string_arg("-c") {
        Some(class) => class.to_string(),
        None => {
            println!("No class name specified");
            return;
        }
    };

    method_name = match args.get_string_arg("-m") {
        Some(method) => method.to_string(),
        None => {
            println!("No method name specified");
            return;
        }
    };

    match injector.eject(assembly, &namespace, &class_name, &method_name) {
        Ok(_) => println!("Ejection successful"),
        Err(e) => println!("Ejection failed: {}", e),
    }
}

fn format_address<T: Display + std::fmt::UpperHex>(address: T, is_64_bit: bool) -> String {
    if is_64_bit { format!("0x{:016X}", address) } else { format!("0x{:08X}", address) }
}
