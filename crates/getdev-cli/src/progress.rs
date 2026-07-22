//! CLI-tier "processing" spinner — stderr only, dependency-free.
//!
//! A tiny rotating-braille indicator so an interactive user sees that a scan is
//! actually running (the parse-once passes can take a couple of seconds on a
//! large repo). It writes ONLY to stderr, so stdout — the findings table, or
//! the `--json` / `-o <file>` report — stays byte-for-byte clean and pipe-safe
//! (the machine-output contract). It auto-suppresses when:
//!   * stderr is not a TTY (CI, pipes, pre-commit hooks) — nothing is written;
//!   * `--json` is set (stdout is machine output);
//!   * `-o <file>` is set (stdout is just the echoed path);
//!   * `--quiet` is set.
//!
//! The spinner frame's color honors `--no-color` and `NO_COLOR`.
//!
//! **Dependency-free on purpose.** getdev's whole pitch is a minimal,
//! auditable, deterministic security tool — one that scans *other* projects for
//! risky/hallucinated dependencies. A decorative spinner must not widen the
//! very supply-chain surface the tool is built to police, so this uses std
//! threads only: no new crate, no async runtime (DEC-01), and nothing here
//! touches stdout or the deterministic findings output.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Braille "dev spinner" frames — the developer-standard rotating dots.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// Frame cadence. Fast enough to read as motion, slow enough to be cheap.
const TICK: Duration = Duration::from_millis(90);

/// A running stderr spinner, or a no-op handle when progress is suppressed.
/// Call [`Progress::phase`] to relabel the live line, and [`Progress::finish`]
/// (or just drop it) to erase the line before anything renders to stdout.
pub struct Progress {
    inner: Option<Spinner>,
}

struct Spinner {
    stop: Arc<AtomicBool>,
    msg: Arc<Mutex<String>>,
    handle: Option<JoinHandle<()>>,
}

impl Progress {
    /// Start a spinner labeled `initial`. `show` should already fold the
    /// output-mode gates (`!json && !quiet && output.is_none()`); TTY detection
    /// on stderr is applied here. When suppressed, every method is a no-op and
    /// not a single byte is ever written.
    pub fn start(show: bool, no_color: bool, initial: &str) -> Self {
        if !show || !std::io::stderr().is_terminal() {
            return Self { inner: None };
        }
        let color = !no_color && std::env::var_os("NO_COLOR").is_none();
        let stop = Arc::new(AtomicBool::new(false));
        let msg = Arc::new(Mutex::new(initial.to_owned()));
        let handle = {
            let stop = Arc::clone(&stop);
            let msg = Arc::clone(&msg);
            thread::spawn(move || spin(&stop, &msg, color))
        };
        Self {
            inner: Some(Spinner {
                stop,
                msg,
                handle: Some(handle),
            }),
        }
    }

    /// Relabel the live spinner line. No-op when suppressed.
    pub fn phase(&self, label: &str) {
        if let Some(sp) = &self.inner {
            if let Ok(mut m) = sp.msg.lock() {
                label.clone_into(&mut m);
            }
        }
    }

    /// Stop the spinner and erase its line so the following stdout render starts
    /// clean. Consumes `self`; dropping without calling this does the same via
    /// [`Drop`].
    pub fn finish(self) {
        drop(self);
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(mut sp) = self.inner.take() {
            sp.stop.store(true, Ordering::Relaxed);
            if let Some(h) = sp.handle.take() {
                let _ = h.join();
            }
        }
    }
}

/// The ticker loop: redraw the current frame + label until `stop`, then erase
/// the line. `\r` returns to column 0 and `\x1b[2K` clears the whole line —
/// both safe here because the caller only starts a spinner when stderr is a
/// TTY. Only the color escape is gated on `color`.
fn spin(stop: &AtomicBool, msg: &Mutex<String>, color: bool) {
    let mut stderr = std::io::stderr();
    let mut i = 0usize;
    while !stop.load(Ordering::Relaxed) {
        let frame = FRAMES[i % FRAMES.len()];
        let label = msg.lock().map(|m| m.clone()).unwrap_or_default();
        let _ = if color {
            write!(stderr, "\r\x1b[2K\x1b[36m{frame}\x1b[0m {label}")
        } else {
            write!(stderr, "\r\x1b[2K{frame} {label}")
        };
        let _ = stderr.flush();
        i += 1;
        thread::sleep(TICK);
    }
    // Erase the line so no spinner residue survives into scrollback.
    let _ = write!(stderr, "\r\x1b[2K");
    let _ = stderr.flush();
}
