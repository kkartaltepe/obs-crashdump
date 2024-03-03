use chrono;
use crash_handler;
use libc;
use minidump_writer;

use std::io;

static mut OBS_MODULE_POINTER: *mut libc::c_void = core::ptr::null_mut();
#[no_mangle]
pub unsafe extern "C" fn obs_module_set_pointer(module: *mut libc::c_void) {
    OBS_MODULE_POINTER = module;
}
#[no_mangle]
pub unsafe fn obs_current_module() -> *const libc::c_void {
    return OBS_MODULE_POINTER;
}
fn sem_to_int(major: u8, minor: u8, patch: u8) -> u32 {
    return ((major as u32) << 24) | ((minor as u32) << 16) | (patch as u32);
}
#[no_mangle]
pub unsafe extern "C" fn obs_module_ver() -> u32 {
    return sem_to_int(0, 28, 0);
}

// os_get_config_path_ptr

#[allow(deprecated)]
#[no_mangle]
pub extern "C" fn obs_module_load() -> bool {
    // Prep crashes dir
    let crashdir = std::path::PathBuf::from(std::env::var("HOME").expect("HOME not set"))
        .join(".config/obs-studio/crashes");
    std::fs::create_dir_all(&crashdir).expect("No crashes dir");
    // Cleanup old entries
    let mut entries = std::fs::read_dir(&crashdir)
        .expect("Couldnt read crashes dir")
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .expect("Couldnt read a crash file");
    if entries.len() > 10 {
        entries.sort();
        for entry in entries.into_iter().skip(10) {
            std::fs::remove_file(entry).expect("Couldnt remove an old crash file");
        }
    }
    let crash_file = crashdir.join(format!(
        "{}.mdump",
        chrono::Local::now().format("%Y-%m-%d-%H-%M-%S")
    ));

    // Install crash handler
    unsafe {
        let mut pipe: [libc::c_int; 2] = [0; 2];
        if libc::pipe(&mut pipe[0]) != 0 {
            println!("Failed to create crash handler pipe");
            return false;
        }
        let child = libc::fork();
        if child == 0 {
            libc::close(pipe[1]);
            // Waiting.
            let mut buf: [u8; 4096] = [0; 4096];
            let cc = loop {
                let ret = libc::read(pipe[0], buf.as_mut_ptr() as *mut libc::c_void, 4096);
                if ret < 0 && *libc::__errno_location() == libc::EAGAIN {
                    continue;
                }
                if ret == 0 {
                    libc::_exit(0);
                }
                if ret < 0 {
                    println!("failed to read dump pipe, exiting");
                    libc::_exit(1);
                }
                break crash_handler::CrashContext::from_bytes(&buf[0..ret as usize]).unwrap();
            };

            // Unfotunate that this allocates so we cant fork late.
            let mut writer = minidump_writer::minidump_writer::MinidumpWriter::new(cc.pid, cc.tid);
            writer.set_crash_context(minidump_writer::crash_context::CrashContext {
                inner: cc.clone(),
            });
            let Ok(mut minidump_file) = std::fs::File::create(&crash_file) else {
                println!("failed to create file");
                libc::_exit(1);
            };
            if let Err(e) = writer.dump(&mut minidump_file) {
                println!("failed to write minidump: {}", e);
                libc::_exit(1)
            };

            libc::_exit(0);
        }
        libc::close(pipe[0]);

        // Parent installs crash handler.
        let ch = crash_handler::CrashHandler::attach(crash_handler::make_crash_event(
            move |cc: &crash_handler::CrashContext| {
                let bytes = cc.as_bytes();
                libc::write(pipe[1], bytes.as_ptr() as *const libc::c_void, bytes.len());
                let mut status = 0;
                libc::waitpid(child, &mut status, 0);
                return crash_handler::CrashEventResult::Handled(true); // Let coredumpctl and
                                                                       // debuggers capture the
                                                                       // rest.
            },
        ))
        .unwrap();
        std::mem::forget(ch);
    }
    return true;
}
