//! Global retained-message memory accounting.

use std::sync::{Arc, Mutex};

// ── Memory budget ──────────────────────────────────────────────────

/// RAII guard that holds `bytes` reserved from a [`MemoryBudget`].
///
/// On drop the reserved bytes are returned to the budget. The guard
/// is *not* cloneable — moving it transfers ownership of the
/// reservation; cloning would cause a double-release.
pub struct MemoryReservation {
    inner: Arc<Mutex<usize>>,
    bytes: usize,
}

impl std::fmt::Debug for MemoryReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryReservation")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        let mut used = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *used = used.saturating_sub(self.bytes);
    }
}

/// A global, thread-safe memory budget for retained message payloads.
///
/// The budget bounds the total bytes of in-flight messages regardless
/// of connection count. It is backed by `Arc<Mutex<usize>>` so
/// reservations can be shared across threads.
#[derive(Clone, Debug)]
pub struct MemoryBudget {
    inner: Arc<Mutex<usize>>,
    capacity: usize,
}

impl MemoryBudget {
    /// Create a new budget allowing up to `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(0)),
            capacity,
        }
    }

    /// Try to reserve `bytes` from the budget.
    ///
    /// Returns `Some(MemoryReservation)` on success, or `None` if the
    /// reservation would exceed capacity **or** would cause a
    /// checked-add overflow (defending against `usize::MAX` attacks).
    pub fn try_reserve(&self, bytes: usize) -> Option<MemoryReservation> {
        let mut used = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let new_total = used.checked_add(bytes)?;
        if new_total > self.capacity {
            return None;
        }
        *used = new_total;
        Some(MemoryReservation {
            inner: Arc::clone(&self.inner),
            bytes,
        })
    }

    /// Current bytes in use (snapshot; may change immediately after).
    pub fn used(&self) -> usize {
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Total capacity of this budget.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_is_released_on_drop() {
        let budget = MemoryBudget::new(100);
        let first = budget.try_reserve(80).unwrap();
        assert!(budget.try_reserve(21).is_none());
        drop(first);
        assert!(budget.try_reserve(100).is_some());
    }

    #[test]
    fn zero_reservation_succeeds() {
        let budget = MemoryBudget::new(100);
        let r = budget.try_reserve(0).unwrap();
        assert_eq!(budget.used(), 0);
        drop(r);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exact_limit_succeeds() {
        let budget = MemoryBudget::new(100);
        let r = budget.try_reserve(100).unwrap();
        assert_eq!(budget.used(), 100);
        drop(r);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn one_over_rejected() {
        let budget = MemoryBudget::new(100);
        assert!(budget.try_reserve(101).is_none());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn checked_add_overflow_rejected() {
        let budget = MemoryBudget::new(usize::MAX);
        let _r = budget.try_reserve(usize::MAX).unwrap();
        // second reservation would overflow usize — must return None, not panic
        assert!(budget.try_reserve(1).is_none());
    }

    #[test]
    fn poisoned_budget_lock_recovers_without_panicking() {
        use std::thread;

        let budget = MemoryBudget::new(100);
        let poisoned = budget.clone();
        let _ = thread::spawn(move || {
            let _guard = poisoned.inner.lock().unwrap();
            panic!("poison budget lock for recovery test");
        })
        .join();

        let reservation = budget.try_reserve(40).unwrap();
        assert_eq!(budget.used(), 40);
        drop(reservation);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn concurrent_reservations_never_exceed_budget() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let budget = MemoryBudget::new(1000);
        let barrier = Arc::new(Barrier::new(21));
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let b = budget.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let reservation = b.try_reserve(100);
                    // Every thread attempts exactly once, then all wait while
                    // successful guards are still alive. This makes the test
                    // about simultaneous reservations rather than scheduling.
                    barrier.wait();
                    reservation
                })
            })
            .collect();
        barrier.wait();

        let mut successes = 0;
        for h in handles {
            if h.join().unwrap().is_some() {
                successes += 1;
            }
        }
        // At most 10 threads (10 × 100 = 1000) can hold a reservation.
        assert!(successes <= 10);
        // After all threads finish, all reservations are released.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn drop_releases_exactly_once() {
        let budget = MemoryBudget::new(100);
        {
            let _r1 = budget.try_reserve(30).unwrap();
            let _r2 = budget.try_reserve(40).unwrap();
            assert_eq!(budget.used(), 70);
        }
        // Both dropped — back to zero.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn moving_reservation_transfers_ownership() {
        let budget = MemoryBudget::new(100);
        let r = budget.try_reserve(50).unwrap();
        assert_eq!(budget.used(), 50);
        // Move into a function — original `r` is consumed.
        let moved = move_reservation(r);
        assert_eq!(budget.used(), 50); // still held
        drop(moved);
        assert_eq!(budget.used(), 0); // released exactly once
    }

    fn move_reservation(r: MemoryReservation) -> MemoryReservation {
        r // move, not copy
    }

    // ── Budget integration into read_request ─────────────────────────
}
