use std::sync::atomic::{AtomicUsize, Ordering};

pub const PROGRESS_INTERVAL: usize = 100;

pub struct ProgressReporter {
    label: &'static str,
    total: usize,
    completed: AtomicUsize,
    enabled: bool,
}

impl ProgressReporter {
    pub fn new(label: &'static str, total: usize, enabled: bool) -> Self {
        if enabled {
            eprintln!("{label}: starting {total} tasks");
        }

        Self {
            label,
            total,
            completed: AtomicUsize::new(0),
            enabled,
        }
    }

    pub fn tick(&self) {
        if !self.enabled {
            return;
        }

        let done = self.completed.fetch_add(1, Ordering::Relaxed) + 1;
        if done == self.total || done.is_multiple_of(PROGRESS_INTERVAL) {
            eprintln!("{}: {done}/{}", self.label, self.total);
        }
    }

    pub fn finish(&self) {
        if self.enabled {
            eprintln!("{}: completed {}/{}", self.label, self.total, self.total);
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
        reporter.finish();
    }
}
