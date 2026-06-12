use std::io::{IsTerminal, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const PROGRESS_INTERVAL: usize = 25;

pub fn resolve_show_progress(explicit: bool, no_progress: bool) -> bool {
    if no_progress {
        return false;
    }
    if explicit {
        return true;
    }
    std::io::stderr().is_terminal()
}

pub struct ProgressReporter {
    label: &'static str,
    total: usize,
    completed: AtomicUsize,
    enabled: bool,
    live: bool,
    write_lock: Mutex<()>,
}

impl ProgressReporter {
    pub fn new(label: &'static str, total: usize, enabled: bool) -> Self {
        let live = enabled && std::io::stderr().is_terminal();
        if enabled && !live {
            eprintln!("{label}: starting {total} tasks");
        }

        Self {
            label,
            total,
            completed: AtomicUsize::new(0),
            enabled,
            live,
            write_lock: Mutex::new(()),
        }
    }

    #[allow(dead_code)]
    pub fn tick(&self) {
        self.tick_with_detail(None);
    }

    pub fn tick_with_detail(&self, detail: Option<&str>) {
        if !self.enabled {
            return;
        }

        let done = self.completed.fetch_add(1, Ordering::Relaxed) + 1;
        if self.live {
            self.render_live_line(done, detail);
        } else if done == self.total || done.is_multiple_of(PROGRESS_INTERVAL) {
            self.println_line(done, detail);
        }
    }

    pub fn finish(&self) {
        if !self.enabled {
            return;
        }

        if self.live {
            let message = format!("{}: completed {}/{}", self.label, self.total, self.total);
            let _guard = self
                .write_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let stderr = std::io::stderr();
            let mut lock = stderr.lock();
            let _ = writeln!(lock, "\r{message:<96}");
            let _ = lock.flush();
        } else {
            eprintln!("{}: completed {}/{}", self.label, self.total, self.total);
        }
    }

    pub fn message(&self, text: &str) {
        if !self.enabled {
            return;
        }

        if self.live {
            let message = format!("{}: {text}", self.label);
            let _guard = self
                .write_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let stderr = std::io::stderr();
            let mut lock = stderr.lock();
            let _ = writeln!(lock, "\r{message:<96}");
            let _ = lock.flush();
        } else {
            eprintln!("{}: {text}", self.label);
        }
    }

    fn render_live_line(&self, done: usize, detail: Option<&str>) {
        let percent = if self.total > 0 {
            done.saturating_mul(100) / self.total
        } else {
            100
        };
        let detail = detail.unwrap_or("");
        let message = if detail.is_empty() {
            format!("{}: {done}/{} ({percent}%)", self.label, self.total)
        } else {
            format!(
                "{}: {done}/{} ({percent}%) {detail}",
                self.label, self.total
            )
        };

        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        let _ = write!(lock, "\r{message:<96}");
        let _ = lock.flush();
    }

    fn println_line(&self, done: usize, detail: Option<&str>) {
        if let Some(detail) = detail.filter(|value| !value.is_empty()) {
            eprintln!("{}: {done}/{} — {detail}", self.label, self.total);
        } else {
            eprintln!("{}: {done}/{}", self.label, self.total);
        }
    }
}

pub struct PhaseReporter {
    label: &'static str,
    enabled: bool,
}

impl PhaseReporter {
    pub fn new(label: &'static str, enabled: bool) -> Self {
        Self { label, enabled }
    }

    pub fn start(&self, phase: &str) {
        if self.enabled {
            eprintln!("{}: {phase}...", self.label);
        }
    }

    pub fn done(&self, phase: &str, detail: &str) {
        if self.enabled {
            eprintln!("{}: {phase} — {detail}", self.label);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_reporter_does_not_panic() {
        let reporter = ProgressReporter::new("test", 10, false);
        reporter.tick();
        reporter.tick_with_detail(Some("host"));
        reporter.message("phase");
        reporter.finish();
    }

    #[test]
    fn resolve_show_progress_respects_no_progress() {
        assert!(!resolve_show_progress(true, true));
        assert!(!resolve_show_progress(false, true));
    }

    #[test]
    fn resolve_show_progress_honors_explicit_flag() {
        assert!(resolve_show_progress(true, false));
    }

    #[test]
    fn phase_reporter_is_silent_when_disabled() {
        let reporter = PhaseReporter::new("analyze", false);
        reporter.start("loading evidence");
        reporter.done("loading evidence", "done");
    }
}
