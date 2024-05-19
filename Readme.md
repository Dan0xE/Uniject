# Uniject

> [!NOTE]
> Most of the Readme has been taken 1:1 from SharpMonoInjector since Uniject does the exact same!

Uniject is a tool for injecting assemblies into Mono embedded applications, commonly Unity Engine based games, written in Rust. It is a rewrite of the [SharpMonoInjector](https://github.com/warbler/SharpMonoInjector/) tool, offering the same functionality.

The target process _usually_ does not have to be restarted in order to inject an updated version of the assembly. Your unload method must destroy all of its resources (such as game objects).

Uniject works by dynamically generating machine code, writing it to the target process, and executing it using CreateRemoteThread. The code calls functions in the Mono embedded API. The return value is obtained with ReadProcessMemory.

Both x86 and x64 processes are supported.

In order for the injector to work, the load/unload methods need to match the following method signature:

```csharp
static void Method()
```

### Upcoming GUI Version

A GUI version of Uniject is currently in development and will be released very soon.

### Example Assemblies

You can find example assemblies to use with Uniject at the SharpMonoInjector Repository: [here](https://github.com/warbler/SharpMonoInjector/tree/master/src/ExampleAssembly)

These example assemblies demonstrate how to properly structure your code for injection and provide a starting point for creating your own assemblies.

### Releases

In the releases section, you will find the console version available for download.

### Credits

Uniject was created as a learning project to explore different injection techniques and to provide an improved version of the original SharpMonoInjector tool.

If you like this project, please also check out the original repo [here](https://github.com/warbler/SharpMonoInjector).

Credits go to [warbler](https://github.com/warbler).
