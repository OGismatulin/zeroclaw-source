#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn shell_quote(path: &Path) -> String {
    shell_quote_text(&path.display().to_string())
}

fn shell_quote_text(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn registered_job(pid_file: &Path, command: &str) -> String {
    format!(
        "/bin/sh -c {} sh",
        shell_quote_text(&format!(
            "printf '%s\\n' \"$$\" > {}; exec env {command}",
            shell_quote(pid_file)
        ))
    )
}

fn daemon_fixture() -> (tempfile::TempDir, std::path::PathBuf, u16, String) {
    let config_dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        config_dir.path().join("config.toml"),
        format!("[gateway]\nport = {port}\nrequire_pairing = false\n"),
    )
    .unwrap();
    let data_dir = config_dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let obstruction = data_dir.join("daemon.sock");
    std::fs::create_dir(&obstruction).unwrap();
    let command = format!(
        "LC_ALL=C TERM=dumb {} --config-dir {} daemon --port {port} --allow-degraded-security",
        shell_quote(Path::new(env!("CARGO_BIN_EXE_zeroclaw"))),
        shell_quote(config_dir.path()),
    );
    (config_dir, obstruction, port, command)
}

fn endpoint_probe(script: &Path, socket: &Path, port: u16, budget: u64) -> String {
    let probe = r#"
import http.client, socket, sys, time
deadline = time.monotonic() + float(sys.argv[3])
while (remaining := deadline - time.monotonic()) > 0:
    connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[2]), timeout=min(0.25, remaining))
    try:
        connection.request("GET", "/health")
        if connection.getresponse().status == 200:
            with socket.socket(socket.AF_UNIX) as rpc:
                rpc.settimeout(min(0.25, max(0.001, deadline - time.monotonic())))
                rpc.connect(sys.argv[1])
                rpc.sendall(b'{"jsonrpc":"2.0","method":"initialize","params":{"protocol_version":1},"id":1}\n')
                if b'"result"' in rpc.recv(4096):
                    print("ENDPOINTS_READY")
                    sys.exit(0)
    except (OSError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    time.sleep(0.05)
print("ENDPOINTS_TIMEOUT")
sys.exit(1)
"#;
    std::fs::write(script, probe).expect("write the endpoint probe");
    format!(
        "python3 {} {} {port} {budget}",
        shell_quote(script),
        shell_quote(socket),
    )
}

fn http_status(port: u16, request: &[u8]) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    stream.write_all(request).ok()?;

    let mut response = [0_u8; 512];
    let read = stream.read(&mut response).ok()?;
    let status_line = std::str::from_utf8(&response[..read])
        .ok()?
        .lines()
        .next()?;
    status_line.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn daemon_surfaces_retired_wati_config_without_leaking_tokens() {
    let cases = [
        (
            "current",
            r#"schema_version = 3

[gateway]
require_pairing = false

[channels.wati.exact_head_smoke]
enabled = true
api_token = "WATI_CURRENT_PLACEHOLDER_MUST_NOT_APPEAR"
api_url = "https://example.invalid"
allowed_numbers = ["1234567890"]
"#,
            "channels.wati",
            "WATI_CURRENT_PLACEHOLDER_MUST_NOT_APPEAR",
        ),
        (
            "legacy",
            r#"[gateway]
require_pairing = false

[channels_config.wati]
enabled = true
api_token = "WATI_LEGACY_PLACEHOLDER_MUST_NOT_APPEAR"
api_url = "https://example.invalid"
allowed_numbers = ["1234567890"]
"#,
            "channels_config.wati",
            "WATI_LEGACY_PLACEHOLDER_MUST_NOT_APPEAR",
        ),
    ];

    for (case, raw_config, expected_path, placeholder) in cases {
        let config_dir = tempfile::tempdir().unwrap();
        std::fs::write(config_dir.path().join("config.toml"), raw_config).unwrap();
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let mut child = Command::new(env!("CARGO_BIN_EXE_zeroclaw"))
            .arg("--config-dir")
            .arg(config_dir.path())
            .arg("daemon")
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--allow-degraded-security")
            .env("LC_ALL", "C")
            .env("TERM", "dumb")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let health_request =
            b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut health_status = None;
        let mut early_exit = None;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                early_exit = Some(status);
                break;
            }
            health_status = http_status(port, health_request);
            if health_status == Some(200) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        if early_exit.is_some() || health_status != Some(200) {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "{case} daemon failed before health readiness: exit={early_exit:?}, health={health_status:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }

        let body = r#"{"text":"hello","waId":"1234567890","fromMe":false}"#;
        let request = format!(
            "POST /wati HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let post_status = http_status(port, request.as_bytes());

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(health_status, Some(200), "{case}: daemon health");
        assert!(
            matches!(post_status, Some(404 | 405)),
            "{case}: retired POST /wati must be unavailable, got {post_status:?}"
        );
        assert!(
            stderr.contains("retired WATI channel config section")
                && stderr.contains(expected_path),
            "{case}: stderr must name retired path {expected_path}: {stderr}"
        );
        assert!(
            !stdout.contains(placeholder) && !stderr.contains(placeholder),
            "{case}: placeholder WATI token leaked to process output"
        );
    }
}

#[test]
fn daemon_guidance_does_not_advertise_unhandled_sigusr1() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let main_source = std::fs::read_to_string(root.join("src/main.rs")).unwrap();
    assert!(
        !main_source.contains("SIGUSR1"),
        "daemon guidance must not advertise the unsupported SIGUSR1 reload path"
    );
}

fn read_pid(directory: &Path, name: &str) -> Option<libc::pid_t> {
    std::fs::read_to_string(directory.join(name))
        .ok()?
        .trim()
        .parse::<libc::pid_t>()
        .ok()
        .filter(|pid| *pid > 1)
}

struct PtyDriver<'a> {
    child: Child,
    sessions: [&'a Path; 2],
}

impl PtyDriver<'_> {
    fn live_groups(&self) -> Vec<libc::pid_t> {
        let mut groups = Vec::new();
        for directory in self.sessions {
            let Some(session) = read_pid(directory, "shell.pid") else {
                continue;
            };
            for name in ["daemon.pid", "probe.pid", "shell.pid"] {
                if let Some(pid) = read_pid(directory, name) {
                    // A registered job must still belong to its own PTY session.
                    if unsafe { libc::getsid(pid) == session && libc::getpgid(pid) == pid } {
                        groups.push(pid);
                    }
                }
            }
        }
        groups
    }

    fn cleanup(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_none() {
            // Freeze the controller before inventorying the groups it created.
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGSTOP) };
            self.child.kill()?;
            self.child.wait()?;
        }
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            for group in self.live_groups() {
                unsafe { libc::kill(-group, signal) };
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if self.live_groups().is_empty() {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Err(std::io::Error::other(format!(
            "owned PTY groups survived cleanup: {:?}",
            self.live_groups()
        )))
    }
}

impl Drop for PtyDriver<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("PTY fixture cleanup: {error}");
        }
    }
}

fn run_pty_transitions(fault: &str) -> (ExitStatus, String) {
    let (foreground, foreground_obstruction, foreground_port, foreground_command) =
        daemon_fixture();
    let (background, background_obstruction, _, background_command) = daemon_fixture();
    let foreground_probe = endpoint_probe(
        &foreground.path().join("endpoint_probe.py"),
        &foreground_obstruction,
        foreground_port,
        if fault == "endpoint" { 1 } else { 12 },
    );
    let stdout = foreground.path().join("expect.stdout");
    let stderr = foreground.path().join("expect.stderr");
    let background_job = if fault == "banner-timeout" {
        "sleep 5"
    } else {
        &background_command
    };
    let child = Command::new("expect")
        .args(["-c", include_str!("fixtures/daemon_startup_feedback.exp")])
        .env("PTY_FAULT", fault)
        .env("PTY_FOREGROUND_SHELL", foreground.path().join("shell.pid"))
        .env("PTY_BACKGROUND_SHELL", background.path().join("shell.pid"))
        .env("PTY_FOREGROUND_OBSTRUCTION", &foreground_obstruction)
        .env("PTY_BACKGROUND_OBSTRUCTION", &background_obstruction)
        .env(
            "PTY_FOREGROUND_COMMAND",
            registered_job(&foreground.path().join("daemon.pid"), &foreground_command),
        )
        .env(
            "PTY_BACKGROUND_COMMAND",
            registered_job(&background.path().join("daemon.pid"), background_job),
        )
        .env(
            "PTY_PROBE_COMMAND",
            registered_job(&foreground.path().join("probe.pid"), &foreground_probe),
        )
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .expect("expect must be installed for the PTY regression test");
    let mut driver = PtyDriver {
        child,
        sessions: [foreground.path(), background.path()],
    };
    let deadline = Instant::now() + Duration::from_secs(25);
    let status = loop {
        if let Some(status) = driver.child.try_wait().expect("poll PTY controller") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let cleanup = driver.cleanup();
    let transcript = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&std::fs::read(&stdout).unwrap()),
        String::from_utf8_lossy(&std::fs::read(&stderr).unwrap()),
    );
    assert!(cleanup.is_ok(), "{cleanup:?}\n{transcript}");
    (
        status.unwrap_or_else(|| panic!("PTY controller deadline expired\n{transcript}")),
        transcript,
    )
}

#[test]
fn daemon_feedback_follows_foreground_job_control_transitions() {
    let (status, transcript) = run_pty_transitions("");
    assert!(
        status.success(),
        "production-binary PTY transitions failed with {status}\n{transcript}"
    );
}

#[test]
fn pty_reports_endpoint_readiness_timeout() {
    let (status, transcript) = run_pty_transitions("endpoint");
    assert!(!status.success(), "{transcript}");
    assert!(
        transcript.contains("endpoint readiness: timeout"),
        "{transcript}"
    );
    assert!(transcript.contains("ENDPOINTS_TIMEOUT"), "{transcript}");
}

#[test]
fn pty_reports_missing_ready_banner() {
    for (fault, reason) in [("banner-timeout", "timeout"), ("banner-eof", "EOF")] {
        let (status, transcript) = run_pty_transitions(fault);
        assert!(!status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("foreground ready banner: {reason}")),
            "{transcript}"
        );
    }
}
