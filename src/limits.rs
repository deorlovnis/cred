//! Time limits in `cred mcp`: how long a consent lasts and how long a browser may sit idle
//! or stay open. The clock is passed in, so the rules are testable. 0 minutes means no limit.

use std::time::{Duration, Instant};

fn minutes(m: u64) -> Option<Duration> {
    (m > 0).then(|| Duration::from_secs(m.saturating_mul(60)))
}

/// Whether a consent given at `granted` still counts at `now`.
pub fn consent_holds(granted: Instant, now: Instant, consent_minutes: u64) -> bool {
    minutes(consent_minutes).and_then(|d| granted.checked_add(d)).is_none_or(|end| now < end)
}

/// The deadlines of one open browser.
pub struct Lease {
    opened: Instant,
    used: Instant,
    idle: Option<Duration>,
    max: Option<Duration>,
}

impl Lease {
    pub fn new(now: Instant, idle_minutes: u64, max_minutes: u64) -> Self {
        Self { opened: now, used: now, idle: minutes(idle_minutes), max: minutes(max_minutes) }
    }

    pub fn touch(&mut self, now: Instant) {
        self.used = now;
    }

    /// When the browser must close unless it is used again, if it ever must.
    pub fn deadline(&self) -> Option<Instant> {
        let idle = self.idle.and_then(|d| self.used.checked_add(d));
        let max = self.max.and_then(|d| self.opened.checked_add(d));
        idle.into_iter().chain(max).min()
    }

    pub fn expired(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|d| now >= d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(t: Instant, mins: u64) -> Instant {
        t + Duration::from_secs(mins * 60)
    }

    #[test]
    fn consent_lapses_after_its_time() {
        let t = Instant::now();
        assert!(consent_holds(t, after(t, 239), 240));
        assert!(!consent_holds(t, after(t, 240), 240));
        assert!(consent_holds(t, after(t, 100_000), 0));
    }

    #[test]
    fn idle_browser_expires_and_use_extends_it() {
        let t = Instant::now();
        let mut lease = Lease::new(t, 10, 60);
        assert!(!lease.expired(after(t, 9)));
        assert!(lease.expired(after(t, 10)));
        lease.touch(after(t, 9));
        assert!(!lease.expired(after(t, 18)));
        assert_eq!(lease.deadline(), Some(after(t, 19)));
    }

    #[test]
    fn total_length_is_capped_however_busy() {
        let t = Instant::now();
        let mut lease = Lease::new(t, 10, 60);
        for m in (5..=55).step_by(5) {
            lease.touch(after(t, m));
            assert!(!lease.expired(after(t, m)));
        }
        lease.touch(after(t, 59));
        assert_eq!(lease.deadline(), Some(after(t, 60)));
        assert!(lease.expired(after(t, 60)));
    }

    #[test]
    fn zero_means_no_limit() {
        let t = Instant::now();
        assert_eq!(Lease::new(t, 0, 0).deadline(), None);
        assert!(!Lease::new(t, 0, 0).expired(after(t, 100_000)));
        assert_eq!(Lease::new(t, 0, 30).deadline(), Some(after(t, 30)));
        assert_eq!(Lease::new(t, 5, 0).deadline(), Some(after(t, 5)));
        assert_eq!(Lease::new(t, u64::MAX, u64::MAX).deadline(), None);
    }
}
