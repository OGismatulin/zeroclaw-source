use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const WAIT: Duration = Duration::from_secs(5);

pub struct PipeHold(PathBuf);

impl PipeHold {
    pub fn new(directory: &Path) -> Self {
        let path = directory.join("hold");
        fs::write(&path, "").expect("create pipe hold");
        Self(path)
    }
}

impl Drop for PipeHold {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn wait_for<T>(mut probe: impl FnMut() -> Option<T>, failure: &str) -> T {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(Instant::now() < deadline, "{failure}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn holder_pid(directory: &Path) -> u32 {
    wait_for(
        || {
            fs::read_to_string(directory.join("ready"))
                .ok()?
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|pid| (2..=i32::MAX as u32).contains(pid))
        },
        "inherited pipe holder did not publish its PID",
    )
}

pub fn assert_holding(directory: &Path, pid: u32) {
    assert!(
        !directory.join("released").exists(),
        "pipe holder released early"
    );
    #[cfg(unix)]
    assert_eq!(
        unsafe { libc::kill(pid as libc::pid_t, 0) },
        0,
        "pipe holder {pid} exited early"
    );
    #[cfg(not(unix))]
    let _ = pid;
}

pub fn await_release(directory: &Path, pid: u32) {
    wait_for(
        || directory.join("released").exists().then_some(()),
        "inherited pipe holder did not observe release",
    );
    #[cfg(unix)]
    wait_for(
        || {
            let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
            (result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
                .then_some(())
        },
        "inherited pipe holder was not reaped",
    );
    #[cfg(not(unix))]
    let _ = pid;
}
