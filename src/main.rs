#![cfg_attr(test, feature(test))]

extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate libc;
extern crate parity_wasm;
extern crate wasmi;

use std::env;
use std::ffi::CStr;
use std::str::FromStr;
use std::{mem, process};

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

    fn next<T: LittleEndianConvert>(&mut self) -> T {
        let out = T::from_little_endian(self.memory).expect("Memory too short");
        // TODO: Implicit requirement that `LittleEndianConvert::from_little_endian`
        //       consumes exactly `mem::size_of::<T>` bytes.
        self.memory = &self.memory[mem::size_of::<T>()..];
        out
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

static FUNCTIONS: &[(&str, fn(&mut Env, RuntimeArgs) -> Option<RuntimeValue>)] = &[
    unimplemented_ext!("table"),
    ("abort", |_, _| explicit_abort()),
    ("enlargeMemory", |_, _| abort_on_cannot_grow_memory()),
    ("getTotalMemory", |env, _| {
        Some((wasmi::memory_units::Bytes::from(env.memory.current_size()).0 as i32).into())
    }),
    ("abortOnCannotGrowMemory", |_, _| {
        abort_on_cannot_grow_memory()
    }),
    ("invoke_diid", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .diid
            .clone()
            .expect("`invoke_diid` called but `dynCall_diid` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_i", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .i
            .clone()
            .expect("`invoke_i` called but `dynCall_i` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_ii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .ii
            .clone()
            .expect("`invoke_ii` called but `dynCall_ii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iii
            .clone()
            .expect("`invoke_iii` called but `dynCall_iii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iiii
            .clone()
            .expect("`invoke_iiii` called but `dynCall_iiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iiiii
            .clone()
            .expect("`invoke_iiiii` called but `dynCall_iiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iiiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iiiiii
            .clone()
            .expect("`invoke_iiiiii` called but `dynCall_iiiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iiiiiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iiiiiiii
            .clone()
            .expect("`invoke_iiiiiiii` called but `dynCall_iiiiiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iiiiiiiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iiiiiiiiii
            .clone()
            .expect("`invoke_iiiiiiiiii` called but `dynCall_iiiiiiiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_v", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .v
            .clone()
            .expect("`invoke_v` called but `dynCall_v` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_vi", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .vi
            .clone()
            .expect("`invoke_vi` called but `dynCall_vi` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_vii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .vii
            .clone()
            .expect("`invoke_vii` called but `dynCall_vii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viii
            .clone()
            .expect("`invoke_viii` called but `dynCall_viii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viiidd", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viiidd
            .clone()
            .expect("`invoke_viiidd` called but `dynCall_viiidd` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viiii
            .clone()
            .expect("`invoke_viiii` called but `dynCall_viiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viiiii
            .clone()
            .expect("`invoke_viiiii` called but `dynCall_viiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viiiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viiiiii
            .clone()
            .expect("`invoke_viiiiii` called but `dynCall_viiiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viiiiiii", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viiiiiii
            .clone()
            .expect("`invoke_viiiiiii` called but `dynCall_viiiiiii` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_iiiji", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .iiiji
            .clone()
            .expect("`invoke_iiiji` called but `dynCall_iiiji` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_ji", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .ji
            .clone()
            .expect("`invoke_ji` called but `dynCall_ji` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_viiiji", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .viiiji
            .clone()
            .expect("`invoke_viiiji` called but `dynCall_viiiji` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    ("invoke_vji", |env, args| {
        let func_ref = env
            .dyncall
            .as_ref()
            .unwrap()
            .vji
            .clone()
            .expect("`invoke_vji` called but `dynCall_vji` not defined");
        FuncInstance::invoke(&func_ref, &args.as_ref(), env).unwrap()
    }),
    unimplemented_ext!("__Unwind_Backtrace"),
    unimplemented_ext!("__Unwind_FindEnclosingFunction"),
    unimplemented_ext!("__Unwind_GetIPInfo"),
    unimplemented_ext!("___buildEnvironment"),
    ("___cxa_allocate_exception", |env, args| {
        let malloc = env.alloc.as_ref().unwrap().malloc.clone();
        FuncInstance::invoke(&malloc, &args.as_ref(), env).unwrap()
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

        let out = env.memory.with_direct_access_mut(|bytes| {
            let (path, buf): (u32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next(), varargs.next())
            };

            unsafe {
                libc::stat64(
                    bytes[path as usize..].as_ptr() as _,
                    bytes[buf as usize..].as_mut_ptr() as _,
                )
            }
        });

        Some(out.into())
    }),
    ("___syscall221", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: i32 = env.memory.with_direct_access(|bytes| {
            let (fd, cmd): (i32, i32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next(), varargs.next())
            };

            unsafe { libc::fcntl(fd, cmd) }
        });

        Some(out.into())
    }),
    ("___syscall3", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: isize = env.memory.with_direct_access(|bytes| {
            let (fd, buf, count): (i32, u32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next(), varargs.next(), varargs.next())
            };

            unsafe { libc::read(fd, bytes[buf as usize..].as_ptr() as _, count as _) }
        });

        Some((out as i32).into())
    }),
    ("___syscall4", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out: isize = env.memory.with_direct_access(|bytes| {
            let (fd, buf, count): (i32, u32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next(), varargs.next(), varargs.next())
            };

            unsafe { libc::write(fd, bytes[buf as usize..].as_ptr() as _, count as _) }
        });

        Some((out as i32).into())
    }),
    ("___syscall5", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out = env.memory.with_direct_access(|bytes| {
            let (path, flag, mode): (u32, i32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next(), varargs.next(), varargs.next())
            };

            unsafe { libc::open(bytes[path as usize..].as_ptr() as _, flag, mode) }
        });

        Some(out.into())
    }),
    ("___syscall54", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out = env.memory.with_direct_access(|bytes| {
            let (fd, request): (i32, u32) = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                (varargs.next(), varargs.next())
            };

            unsafe { libc::ioctl(fd, request as _) }
        });

        Some(out.into())
    }),
    ("___syscall6", |env, args| {
        // `args.nth(0)` is `which`, which is just the syscall number again
        let ptr: u32 = args.nth(1);

        let out = env.memory.with_direct_access(|bytes| {
            let fd: i32 = {
                let mut varargs = VarArgs::new(&bytes[ptr as usize..]);
                varargs.next()
            };

            unsafe { libc::close(fd) }
        });

        Some(out.into())
    }),
    ("_abort", |_, _| explicit_abort()),
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

        Some(out.into())
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

        Some(out.into())
    }),
    unimplemented_ext!("_dladdr"),
    unimplemented_ext!("_emscripten_memcpy_big"),
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
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        });

        if let Ok(value) = env::var(&string) {
            let allocation = env.malloc(value.as_bytes());
            env.env_allocation = Some(allocation);
            Some(allocation.into())
        } else {
            Some(0i32.into())
        }
    }),
    unimplemented_ext!("_llvm_trap"),
    ("_pthread_cond_destroy", |_, _| Some(0i32.into())),
    ("_pthread_cond_init", |_, _| Some(0i32.into())),
    ("_pthread_cond_signal", |_, _| Some(0i32.into())),
    ("_pthread_cond_timedwait", |_, _| Some(0i32.into())),
    ("_pthread_cond_wait", |_, _| Some(0i32.into())),
    ("_pthread_condattr_destroy", |_, _| Some(0i32.into())),
    ("_pthread_condattr_init", |_, _| Some(0i32.into())),
    ("_pthread_condattr_setclock", |_, _| Some(0i32.into())),
    ("_pthread_mutex_destroy", |_, _| Some(0i32.into())),
    ("_pthread_mutex_init", |_, _| Some(0i32.into())),
    ("_pthread_mutexattr_destroy", |_, _| Some(0i32.into())),
    ("_pthread_mutexattr_init", |_, _| Some(0i32.into())),
    ("_pthread_mutexattr_settype", |_, _| Some(0i32.into())),
    ("_pthread_rwlock_rdlock", |_, _| Some(0i32.into())),
    ("_pthread_rwlock_unlock", |_, _| Some(0i32.into())),
    unimplemented_ext!("_sched_yield"),
    ("_sysconf", |_, args| {
        let name: i32 = args.nth(0);
        let out = unsafe { libc::sysconf(name) } as i32;
        Some(out.into())
    }),
    unimplemented_ext!("___gxx_personality_v0"),
];

struct DynCall {
    diid: Option<FuncRef>,
    i: Option<FuncRef>,
    ii: Option<FuncRef>,
    iii: Option<FuncRef>,
    iiii: Option<FuncRef>,
    iiiii: Option<FuncRef>,
    iiiiii: Option<FuncRef>,
    iiiiiiii: Option<FuncRef>,
    iiiiiiiiii: Option<FuncRef>,
    iiiji: Option<FuncRef>,
    ji: Option<FuncRef>,
    v: Option<FuncRef>,
    vi: Option<FuncRef>,
    vii: Option<FuncRef>,
    viiidd: Option<FuncRef>,
    viii: Option<FuncRef>,
    viiii: Option<FuncRef>,
    viiiii: Option<FuncRef>,
    viiiiii: Option<FuncRef>,
    viiiiiii: Option<FuncRef>,
    viiiji: Option<FuncRef>,
    vji: Option<FuncRef>,
}

impl DynCall {
    fn from_module(module: &ModuleRef) -> Self {
        DynCall {
            diid: module
                .export_by_name("dynCall_diid")
                .and_then(|e| e.as_func().cloned()),
            i: module
                .export_by_name("dynCall_i")
                .and_then(|e| e.as_func().cloned()),
            ii: module
                .export_by_name("dynCall_ii")
                .and_then(|e| e.as_func().cloned()),
            iii: module
                .export_by_name("dynCall_iii")
                .and_then(|e| e.as_func().cloned()),
            iiii: module
                .export_by_name("dynCall_iiii")
                .and_then(|e| e.as_func().cloned()),
            iiiii: module
                .export_by_name("dynCall_iiiii")
                .and_then(|e| e.as_func().cloned()),
            iiiiii: module
                .export_by_name("dynCall_iiiiii")
                .and_then(|e| e.as_func().cloned()),
            iiiiiiii: module
                .export_by_name("dynCall_iiiiiiii")
                .and_then(|e| e.as_func().cloned()),
            iiiiiiiiii: module
                .export_by_name("dynCall_iiiiiiiiii")
                .and_then(|e| e.as_func().cloned()),
            iiiji: module
                .export_by_name("dynCall_iiiji")
                .and_then(|e| e.as_func().cloned()),
            ji: module
                .export_by_name("dynCall_ji")
                .and_then(|e| e.as_func().cloned()),
            v: module
                .export_by_name("dynCall_v")
                .and_then(|e| e.as_func().cloned()),
            vi: module
                .export_by_name("dynCall_vi")
                .and_then(|e| e.as_func().cloned()),
            vii: module
                .export_by_name("dynCall_vii")
                .and_then(|e| e.as_func().cloned()),
            viiidd: module
                .export_by_name("dynCall_viiidd")
                .and_then(|e| e.as_func().cloned()),
            viii: module
                .export_by_name("dynCall_viii")
                .and_then(|e| e.as_func().cloned()),
            viiii: module
                .export_by_name("dynCall_viiii")
                .and_then(|e| e.as_func().cloned()),
            viiiii: module
                .export_by_name("dynCall_viiiii")
                .and_then(|e| e.as_func().cloned()),
            viiiiii: module
                .export_by_name("dynCall_viiiiii")
                .and_then(|e| e.as_func().cloned()),
            viiiiiii: module
                .export_by_name("dynCall_viiiiiii")
                .and_then(|e| e.as_func().cloned()),
            viiiji: module
                .export_by_name("dynCall_viiiji")
                .and_then(|e| e.as_func().cloned()),
            vji: module
                .export_by_name("dynCall_vji")
                .and_then(|e| e.as_func().cloned()),
        }
    }
}

struct Alloc {
    malloc: FuncRef,
    free: FuncRef,
}

impl Alloc {
    fn from_module(module: &ModuleRef) -> Self {
        Alloc {
            malloc: module
                .export_by_name("_malloc")
                .expect("Cannot find function `_malloc`")
                .as_func()
                .unwrap()
                .clone(),
            free: module
                .export_by_name("_free")
                .expect("Cannot find function `_free`")
                .as_func()
                .unwrap()
                .clone(),
        }
    }
}

struct Env {
    pub static_bump: u32,
    pub memory: MemoryRef,
    pub dyncall: Option<DynCall>,
    pub alloc: Option<Alloc>,
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
            dyncall: None,
            alloc: None,
            env_allocation: None,
        }
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
        FUNCTIONS
            .iter()
            .position(|&(n, _)| n == field_name)
            .map(|pos| FuncInstance::alloc_host(sig.clone(), pos))
            .ok_or_else(|| Error::Instantiation(format!("Cannot find function: {}", field_name)))
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
        let (_, func) = FUNCTIONS[index];

        Ok(func(self, args))
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

fn main() {
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
                         file that should have been emitted when compiling your
                         Wasm file.",
                    )
                    .required(true),
            )
            .arg(Arg::with_name("ARGS").multiple(true))
            .get_matches()
    };

    let input = matches.value_of("INPUT").unwrap();
    let module = parity_wasm::deserialize_file(&input).expect("File to be deserialized");

    let static_bump = matches
        .value_of("static-bump")
        .and_then(|v| u32::from_str(v).ok())
        .expect("Invalid number supplied for `static-bump`");

    let loaded_module = wasmi::Module::from_parity_wasm_module(module).expect("Module to be valid");

    // Intialize deserialized module. It adds module into It expects 3 parameters:
    // - a name for the module
    // - a module declaration
    // - "main" module doesn't import native module(s) this is why we don't need to provide external native modules here
    // This test shows how to implement native module https://github.com/NikVolf/parity-wasm/blob/master/src/interpreter/tests/basics.rs#L197
    let mut env = Env::new(
        MemoryInstance::alloc(Pages(256), Some(Pages(256))).expect("Could not allocate memory"),
        static_bump,
    );

    let main = {
        let imports = ImportsBuilder::new()
            .with_resolver("env", &env)
            .with_resolver("global", &Global);

        ModuleInstance::new(&loaded_module, &imports).expect("Failed to instantiate module")
    }
    .run_start(&mut env)
    .expect("Failed to run start for module");

    env.dyncall = Some(DynCall::from_module(&main));
    env.alloc = Some(Alloc::from_module(&main));

    let pointers = iter::once(input)
        .chain(matches.values_of("ARGS").unwrap())
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
            .expect("Failed to invoke `_main`")
            .and_then(wasmi::RuntimeValue::try_into)
            .expect("`_main` didn't return i32"),
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
}
