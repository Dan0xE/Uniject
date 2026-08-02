# Uniject

Uniject is a library for injecting .NET assemblies into processes that embed the Mono
runtime, including many Unity applications. It locates the target's Mono module, resolves the
required embedding APIs, writes a small call stub into the target, and executes it through a
remote thread.

## Platform support

- Windows targets only.
- x86 and x86-64 Mono target processes.
- The target must embed Mono and export the APIs used by Uniject. IL2CPP targets are not
  supported.

## Usage

```no_run
use std::error::Error;
use std::fs;

use uniject::Injector;

fn main() -> Result<(), Box<dyn Error>> {
    let process_id = 1234;
    let raw_assembly = fs::read("Plugin.dll")?;
    let mut injector = Injector::new(process_id)?;

    let assembly = injector.inject(
        &raw_assembly,
        "Plugin",
        "Loader",
        "Load",
    )?;

    injector.eject(assembly, "Plugin", "Loader", "Unload")?;
    Ok(())
}
```

The invoked load and unload methods must be static, parameterless methods:

```csharp
static void Method()
```

## License

Licensed under the [MIT License](https://github.com/Dan0xE/Uniject/blob/main/LICENSE).

[`Injector`]: https://docs.rs/uniject/latest/uniject/struct.Injector.html
