#![cfg_attr(test, feature(test))]

extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate hashbrown;
extern crate libc;
extern crate parity_wasm;
extern crate wasmi;

use std::borrow::Cow;
use std::cell::Cell;
use std::ffi::CStr;
use std::str::FromStr;
use std::{env, mem, process};

use hashbrown::HashMap;

use wasmi::memory_units::Pages;
use wasmi::nan_preserving_float::F64;
use wasmi::{
    Error, Externals, FuncInstance, FuncRef, GlobalInstance, GlobalRef, ImportsBuilder,
    LittleEndianConvert, MemoryInstance, MemoryRef, ModuleImportResolver, ModuleInstance,
    ModuleRef, RuntimeArgs, RuntimeValue, TableInstance, TableRef, Trap,
};

// TODO: Magic number - how is this calculated?
const TOTAL_STACK: u32 = 5242880;

const fn align_memory(ptr: u32) -> u32 {
    (ptr + 15) & !15
}

// TODO: Magic number stolen from the generated JS - how is this calculated?
const DYNAMICTOP_PTR_DIFF: u32 = 1088;

macro_rules! unimplemented_ext {
    ($name:expr) => {
        ($name, |_, _| unimplemented!("{}", $name))
    };
}

struct VarArgs<'a> {
    memory: &'a [u8],
}

impl<'a> VarArgs<'a> {
    fn new(memory: &'a [u8]) -> Self {
        VarArgs { memory }
    }

    fn next<T: LittleEndianConvert>(&mut self) -> Result<T, &'static str> {
        let out = T::from_little_endian(self.memory).map_err(|_| "Memory too short")?;
        // TODO: Implicit requirement that `LittleEndianConvert::from_little_endian`
        //       consumes exactly `mem::size_of::<T>` bytes.
        self.memory = &self.memory[mem::size_of::<T>()..];
        Ok(out)
    }
}

// This is the 32-bit equivalent of the 64-bit `libc::timespec` struct,
// with the `time_t` and `c_long` types substituted for their value
// as defined in `libc::unix::notbsd::linux::other::b32`.
#[repr(C)]
#[derive(Debug)]
struct Timespec32 {
    tv_sec: i32,
    tv_nsec: i32,
}

impl From<libc::timespec> for Timespec32 {
    fn from(other: libc::timespec) -> Self {
        Timespec32 {
            tv_sec: other.tv_sec as _,
            tv_nsec: other.tv_nsec as _,
        }
    }
}

impl From<Timespec32> for libc::timespec {
    fn from(other: Timespec32) -> Self {
        libc::timespec {
            tv_sec: other.tv_sec as _,
            tv_nsec: other.tv_nsec as _,
        }
    }
}

fn abort_on_cannot_grow_memory() -> ! {
    panic!("Cannot grow memory!")
}

/// TODO: This almost certainly happens under usual circumstances, in that case we don't want to panic.
fn explicit_abort() -> ! {
    panic!("Explicit abort!")
}

#[derive(Debug)]
struct HostError(Cow<'static, str>);

impl std::convert::From<&'static str> for HostError {
    fn from(other: &'static str) -> Self {
        HostError(other.into())
    }
}

impl std::convert::From<String> for HostError {
    fn from(other: String) -> Self {
        HostError(other.into())
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl wasmi::HostError for HostError {}

static FUNCTIONS: &[(
    &str,
    fn(&mut Env, RuntimeArgs) -> Result<Option<RuntimeValue>, wasmi::Trap>,
)] = &[
    unimplemented_ext!("table"),
    ("abort", |_, _| explicit_abort()),
    ("_abort", |_, _| explicit_abort()),
    ("enlargeMemory", |_, _| abort_on_cannot_grow_memory()),
    ("getTotalMemory", |env, _| {
        Ok(Some(
            (wasmi::memory_units::Bytes::from(env.memory.current_size()).0 as i32).into(),
        ))
    }),
    ("abortOnCannotGrowMemory", |_, _| {
        abort_on_cannot_grow_memory()
    }),
    unimplemented_ext!("__Unwind_Backtrace"),
    unimplemented_ext!("__Unwind_FindEnclosingFunction"),
    unimplemented_ext!("__Unwind_GetIPInfo"),
    unimplemented_ext!("___buildEnvironment"),
    ("_llvm_trunc_f32", |_env, args| {
        let arg: F64 = args.nth(0);
        Ok(Some(F64::from(arg.to_float().trunc()).into()))
    }),
    ("_llvm_trunc_f64", |_env, args| {
        let arg: F64 = args.nth(0);
        Ok(Some(F64::from(arg.to_float().trunc()).into()))
    }),
    ("f64-rem", |_env, args| {
        let a: F64 = args.nth(0);
        let b: F64 = args.nth(1);
        Ok(Some((a % b).into()))
    }),
    ("___cxa_allocate_exception", |env, args| {
        let malloc = env
            .alloc
            .as_ref()
            .expect("Programmer error: `alloc` was not populated")
            .malloc
            .clone();
        FuncInstance::invoke(&malloc, &args.as_ref(), env)
    }),
    unimplemented_ext!("___cxa_find_matching_catch_2"),
    unimplemented_ext!("___cxa_find_matching_catch_3"),
    unimplemented_ext!("___cxa_free_exception"),
    unimplemented_ext!("___cxa_throw"),
    unimplemented_ext!("___resumeException"),
    unimplemented_ext!("___setErrNo"),
    ("___syscall195", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<_, HostError> = env.memory.with_direct_access_mut(|bytes| {
            let (path, buf): (u32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next()?, varargs.next()?)
            };

            Ok(unsafe {
                libc::stat64(
                    bytes[path as usize..].as_ptr() as _,
                    bytes[buf as usize..].as_mut_ptr() as _,
                )
            })
        });

        Ok(Some(out?.into()))
    }),
    ("___syscall221", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<i32, HostError> = env.memory.with_direct_access(|bytes| {
            let (fd, cmd): (i32, i32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next()?, varargs.next()?)
            };

            Ok(unsafe { libc::fcntl(fd, cmd) })
        });

        Ok(Some(out?.into()))
    }),
    ("___syscall3", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<isize, HostError> = env.memory.with_direct_access(|bytes| {
            let (fd, buf, count): (i32, u32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next()?, varargs.next()?, varargs.next()?)
            };

            Ok(unsafe { libc::read(fd, bytes[buf as usize..].as_ptr() as _, count as _) })
        });

        Ok(Some((out? as i32).into()))
    }),
    ("___syscall4", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<isize, HostError> = env.memory.with_direct_access(|bytes| {
            let (fd, buf, count): (i32, u32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next()?, varargs.next()?, varargs.next()?)
            };

            Ok(unsafe { libc::write(fd, bytes[buf as usize..].as_ptr() as _, count as _) })
        });

        Ok(Some((out? as i32).into()))
    }),
    ("___syscall5", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<_, HostError> = env.memory.with_direct_access(|bytes| {
            let (path, flag, mode): (u32, i32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next()?, varargs.next()?, varargs.next()?)
            };

            Ok(unsafe { libc::open(bytes[path as usize..].as_ptr() as _, flag, mode) })
        });

        Ok(Some(out?.into()))
    }),
    ("___syscall54", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<_, HostError> = env.memory.with_direct_access(|bytes| {
            let (fd, request): (i32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next()?, varargs.next()?)
            };

            Ok(unsafe { libc::ioctl(fd, request as _) })
        });

        Ok(Some(out?.into()))
    }),
    ("___syscall6", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: Result<_, HostError> = env.memory.with_direct_access(|bytes| {
            let fd: i32 = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                varargs.next()?
            };

            Ok(unsafe { libc::close(fd) })
        });

        Ok(Some(out?.into()))
    }),
    ("_clock_gettime", |env, args| {
        use std::ptr;

        let clock_id: i32 = args.nth(0);
        let buf: u32 = args.nth(1);

        let out: i32 = env.memory.with_direct_access_mut(|bytes| {
            let mut out_timespec: libc::timespec = unsafe { mem::uninitialized() };
            let out = unsafe { libc::clock_gettime(clock_id, &mut out_timespec) };

            unsafe {
                ptr::write(
                    &mut bytes[buf as usize] as *mut _ as _,
                    Timespec32::from(out_timespec),
                )
            };

            out
        });

        Ok(Some(out.into()))
    }),
    ("_nanosleep", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let input_ptr: u32 = args.nth(0);
        let output_ptr: u32 = args.nth(1);

        let out = env.memory.with_direct_access_mut(|bytes| {
            use std::ptr;

            let timespec32: Timespec32 = unsafe { mem::transmute_copy(&bytes[input_ptr as usize]) };
            let timespec = libc::timespec::from(timespec32);
            let mut out_timespec = unsafe { mem::uninitialized() };

            let out = unsafe { libc::nanosleep(&timespec, &mut out_timespec) };

            unsafe {
                ptr::write(
                    &mut bytes[output_ptr as usize] as *mut _ as _,
                    Timespec32::from(out_timespec),
                )
            };

            out
        });

        Ok(Some(out.into()))
    }),
    unimplemented_ext!("_dladdr"),
    ("_emscripten_memcpy_big", |env, args| {
        let dst: u32 = args.nth(0);
        let src: u32 = args.nth(1);
        let num: u32 = args.nth(2);

        env.memory
            .copy_nonoverlapping(src as _, dst as _, num as _)
            .map_err(|e| HostError::from(format!("{}", e)))?;

        Ok(Some(dst.into()))
    }),
    unimplemented_ext!("_exit"),
    // TODO: Use libc directly?
    ("_getenv", |env, args| {
        let ptr: u32 = args.nth(0);
        if let Some(alloc) = env.env_allocation.take() {
            env.free(alloc);
        }

        let string = env.memory.with_direct_access(|bytes| {
            let bytes = &bytes[ptr as usize..];
            let first_nul = bytes
                .iter()
                .position(|&n| n == b'\0')
                .expect("String isn't null-terminated");
            CStr::from_bytes_with_nul(&bytes[..first_nul + 1])
                .ok()
                .and_then(|cstr| cstr.to_str().map(str::to_owned).ok())
                .ok_or(HostError::from("`_getenv` passed invalid string"))
        })?;

        if let Ok(value) = env::var(&string) {
            let allocation = env.malloc(value.as_bytes());
            env.env_allocation = Some(allocation);
            Ok(Some(allocation.into()))
        } else {
            Ok(Some(0i32.into()))
        }
    }),
    unimplemented_ext!("_llvm_trap"),
    ("_pthread_cond_destroy", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_cond_init", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_cond_signal", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_cond_timedwait", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_cond_wait", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_condattr_destroy", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_condattr_init", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_condattr_setclock", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_mutex_destroy", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_mutex_init", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_mutexattr_destroy", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_mutexattr_init", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_mutexattr_settype", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_rwlock_rdlock", |_, _| Ok(Some(0i32.into()))),
    ("_pthread_rwlock_unlock", |_, _| Ok(Some(0i32.into()))),
    unimplemented_ext!("_sched_yield"),
    ("_sysconf", |_, args| {
        let name: i32 = args.nth(0);
        let out = unsafe { libc::sysconf(name) } as i32;
        Ok(Some(out.into()))
    }),
    unimplemented_ext!("___gxx_personality_v0"),
];

struct Alloc {
    malloc: FuncRef,
    free: FuncRef,
}

impl Alloc {
    fn from_module(module: &ModuleRef) -> Result<Self, &'static str> {
        Ok(Alloc {
            malloc: module
                .export_by_name("_malloc")
                .ok_or("Cannot find function `_malloc`")?
                .as_func()
                .ok_or("`_malloc` is not a function")?
                .clone(),
            free: module
                .export_by_name("_free")
                .ok_or("Cannot find function `_free`")?
                .as_func()
                .ok_or("`_free` is not a function")?
                .clone(),
        })
    }
}

struct ExceptionInfo {
    pub type_: u32,
    pub destructor: u32,
    pub caught: bool,
    pub rethrown: bool,
}

#[derive(Default)]
struct Exceptions {
    pub infos: HashMap<u32, ExceptionInfo>,
    pub last: Option<u32>,
}

struct Env {
    pub static_bump: u32,
    pub memory: MemoryRef,
    pub invoke: Cell<Result<Vec<FuncRef>, Vec<String>>>,
    pub alloc: Option<Alloc>,
    pub exceptions: Exceptions,
    pub env_allocation: Option<u32>,
}

fn stacktop(static_bump: u32) -> u32 {
    align_memory(dynamictop_ptr(static_bump) + 4)
}

fn stack_max(static_bump: u32) -> u32 {
    stacktop(static_bump) + TOTAL_STACK
}

fn dynamic_base(static_bump: u32) -> u32 {
    align_memory(stack_max(static_bump))
}

fn dynamictop_ptr(static_bump: u32) -> u32 {
    static_bump + DYNAMICTOP_PTR_DIFF
}

impl Env {
    fn new(memory: MemoryRef, static_bump: u32) -> Self {
        memory
            .set_value(dynamictop_ptr(static_bump), dynamic_base(static_bump))
            .expect("Could not set `DYNAMICTOP_PTR`");
        Env {
            memory,
            static_bump,
            exceptions: Exceptions::default(),
            invoke: Cell::new(Err(vec![])),
            alloc: None,
            env_allocation: None,
        }
    }

    fn populate_invoke(&mut self, module: &ModuleRef) -> Result<(), Cow<'static, str>> {
        let out = match self.invoke.replace(Err(vec![])) {
            Ok(funcs) => funcs,
            Err(mut strings) => strings
                .iter()
                .map(|item| {
                    let dyncall = format!("dynCall_{}", item);
                    module
                        .export_by_name(&dyncall)
                        .ok_or_else(|| Cow::from(format!("Cannot find export `{}`", dyncall)))?
                        .as_func()
                        .cloned()
                        .ok_or_else(|| Cow::from(format!("`{}` is not a function", dyncall)))
                })
                .collect::<Result<Vec<_>, _>>()?,
        };

        self.invoke.set(Ok(out));

        Ok(())
    }

    fn dynamictop_ptr(&self) -> u32 {
        dynamictop_ptr(self.static_bump)
    }

    fn stacktop(&self) -> u32 {
        stacktop(self.static_bump)
    }

    #[allow(dead_code)]
    fn stack_max(&self) -> u32 {
        stack_max(self.static_bump)
    }

    #[allow(dead_code)]
    fn dynamic_base(&self) -> u32 {
        dynamic_base(self.static_bump)
    }

    fn malloc(&mut self, to_write: &[u8]) -> u32 {
        if to_write.len() == 0 {
            return 0;
        }

        let malloc = self.alloc.as_ref().unwrap().malloc.clone();
        let allocation = FuncInstance::invoke(&malloc, &[(to_write.len() as u32).into()], self)
            .unwrap()
            .unwrap()
            .try_into::<u32>()
            .unwrap();

        self.memory.with_direct_access_mut(|bytes| {
            let allocation = allocation as usize;
            bytes[allocation..allocation + to_write.len()].copy_from_slice(to_write);
        });

        allocation
    }

    fn free(&mut self, ptr: u32) {
        let free = self.alloc.as_ref().unwrap().free.clone();
        FuncInstance::invoke(&free, &[ptr.into()], self).unwrap();
    }
}

impl ModuleImportResolver for Env {
    fn resolve_func(&self, field_name: &str, sig: &wasmi::Signature) -> Result<FuncRef, Error> {
        const INVOKE_PREFIX: &str = "invoke_";

        if field_name.starts_with(INVOKE_PREFIX) {
            let mut fields = self.invoke.replace(Err(vec![])).unwrap_err();
            let new_index = fields.len();
            fields.push(field_name.trim_start_matches(INVOKE_PREFIX).to_string());
            self.invoke.set(Err(fields));
            Ok(FuncInstance::alloc_host(
                sig.clone(),
                std::usize::MAX - new_index,
            ))
        } else {
            FUNCTIONS
                .iter()
                .position(|&(n, _)| n == field_name)
                .map(|pos| FuncInstance::alloc_host(sig.clone(), pos))
                .ok_or_else(|| {
                    Error::Instantiation(format!("Cannot find function: {}", field_name))
                })
        }
    }

    fn resolve_memory(
        &self,
        field_name: &str,
        descriptor: &wasmi::MemoryDescriptor,
    ) -> Result<MemoryRef, Error> {
        if field_name == "memory" {
            assert_eq!(descriptor.initial(), self.memory.initial().0 as _);
            assert_eq!(
                descriptor.maximum(),
                self.memory.maximum().map(|p| p.0 as _)
            );
            Ok(self.memory.clone())
        } else {
            Err(Error::Instantiation(format!(
                "Cannot find memory: {}",
                field_name
            )))
        }
    }

    fn resolve_global(
        &self,
        field_name: &str,
        _: &wasmi::GlobalDescriptor,
    ) -> Result<GlobalRef, Error> {
        match field_name {
            "STACKTOP" => Ok(GlobalInstance::alloc(self.stacktop().into(), false)),
            "STACK_MAX" => Ok(GlobalInstance::alloc(self.stack_max().into(), false)),
            "DYNAMICTOP_PTR" => Ok(GlobalInstance::alloc(self.dynamictop_ptr().into(), false)),
            "tableBase" => Ok(GlobalInstance::alloc(0.into(), false)),
            _ => Err(Error::Instantiation(format!(
                "Cannot find global: {}",
                field_name
            ))),
        }
    }

    fn resolve_table(
        &self,
        field_name: &str,
        descriptor: &wasmi::TableDescriptor,
    ) -> Result<TableRef, Error> {
        match field_name {
            "table" => TableInstance::alloc(descriptor.initial(), descriptor.maximum()),
            _ => Err(Error::Instantiation(format!(
                "Cannot find table: {}",
                field_name
            ))),
        }
    }
}

impl Externals for Env {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        if let Some((_, func)) = FUNCTIONS.get(index) {
            func(self, args)
        } else {
            let funcs = self
                .invoke
                .replace(Err(vec![]))
                .expect("Programmer error: invoke functions were not populated");
            let index = std::usize::MAX - index;
            let func = funcs[index].clone();
            self.invoke.set(Ok(funcs));
            let out = FuncInstance::invoke(&func, &args.as_ref(), self);
            out
        }
    }
}

struct Global;

impl ModuleImportResolver for Global {
    fn resolve_global(
        &self,
        field_name: &str,
        _: &wasmi::GlobalDescriptor,
    ) -> Result<GlobalRef, Error> {
        match field_name {
            "NaN" => Ok(GlobalInstance::alloc(
                F64::from_float(std::f64::NAN).into(),
                false,
            )),
            "Infinity" => Ok(GlobalInstance::alloc(
                F64::from_float(std::f64::INFINITY).into(),
                false,
            )),
            _ => Err(Error::Instantiation(format!(
                "Cannot find global: {}",
                field_name
            ))),
        }
    }
}

fn main() -> Result<(), Cow<'static, str>> {
    use std::iter;

    let matches = {
        use clap::{AppSettings, Arg};

        app_from_crate!()
            .setting(AppSettings::TrailingVarArg)
            .arg(
                Arg::with_name("INPUT")
                    .help(
                        "Set the wasm file to run. This should be generated \
                         by emscripten, if programming in Rust you can do \
                         `cargo build --target=wasm32-unknown-emscripten`.",
                    )
                    .required(true),
            )
            .arg(
                Arg::with_name("static-bump")
                    .short("s")
                    .long("static-bump")
                    .takes_value(true)
                    .help(
                        "The value of `STATIC_BUMP` in the generated JavaScript \
                         file that should have been emitted when compiling your \
                         Wasm file.",
                    )
                    .required(true),
            )
            .arg(Arg::with_name("ARGS").multiple(true).help(
                "Any arguments to pass to the binary to be run. To pass arguments \
                 that start with `-` or `--`, you have to have a single `--` argument \
                 before the rest of the arguments to prevent these arguments being \
                 passed to `runwasm` itself, like so: `runwasm -s 1234 foo.wasm -- \
                 --help`",
            ))
            .get_matches()
    };

    let input = matches.value_of("INPUT").unwrap();
    let module =
        parity_wasm::deserialize_file(&input).map_err(|_| "Input file is not valid Wasm")?;

    let static_bump = matches
        .value_of("static-bump")
        .and_then(|v| u32::from_str(v).ok())
        .ok_or("Invalid number supplied for `static-bump`")?;

    let loaded_module =
        wasmi::Module::from_parity_wasm_module(module).map_err(|_| "Input module is invalid")?;

    // Intialize deserialized module. It adds module into It expects 3 parameters:
    // - a name for the module
    // - a module declaration
    // - "main" module doesn't import native module(s) this is why we don't need to provide external native modules here
    // This test shows how to implement native module https://github.com/NikVolf/parity-wasm/blob/master/src/interpreter/tests/basics.rs#L197
    let mut env = Env::new(
        MemoryInstance::alloc(Pages(256), Some(Pages(256)))
            .map_err(|_| "Could not allocate memory")?,
        static_bump,
    );

    let main = {
        let imports = ImportsBuilder::new()
            .with_resolver("env", &env)
            .with_resolver("asm2wasm", &env)
            .with_resolver("global", &Global);

        ModuleInstance::new(&loaded_module, &imports).map_err(|e| format!("{}", e))
    }?;
    let main = main
        .run_start(&mut env)
        .map_err(|_| "Failed to run start for module")?;

    env.populate_invoke(&main)?;
    env.alloc = Some(Alloc::from_module(&main)?);

    let pointers = iter::once(input)
        .chain(matches.values_of("ARGS").unwrap_or_default())
        .map(|arg| env.malloc(arg.as_bytes()))
        .collect::<Vec<_>>();

    let mut pointer_bytes: Vec<u8> = vec![0; mem::size_of::<u32>() * pointers.len()];
    for (i, p) in pointers.iter().enumerate() {
        p.into_little_endian(&mut pointer_bytes[i * mem::size_of::<u32>()..]);
    }

    let argc = env.malloc(&pointer_bytes);
    let argv = pointers.len() as u32;

    process::exit(
        main.invoke_export("_main", &[argv.into(), argc.into()], &mut env)
            .map_err(|_| "Failed to invoke `_main`")?
            .and_then(wasmi::RuntimeValue::try_into)
            .ok_or("`_main` didn't return i32")?,
    )
}

#[cfg(test)]
mod tests {
    extern crate test;

    #[bench]
    fn it_works(b: &mut test::Bencher) {
        b.iter(|| {
            ::std::thread::sleep_ms(1);
        });
    }

    #[test]
    fn fails() {
        assert!(0 == 1);
    }
}
