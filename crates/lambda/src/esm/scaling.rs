//! Bounded, reactive SQS polling. Queued workers sleep until admitted by the controller.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::{PollError, PollOutcome};

struct State {
    desired: u32,
    running: u32,
    failures: u32,
    next_poll: Instant,
}

pub(crate) struct PollingControl {
    maximum: u32,
    idle_floor: u32,
    state: Mutex<State>,
    changed: Notify,
}

impl PollingControl {
    pub(crate) fn new(maximum: u32, maximum_configured: bool) -> Arc<Self> {
        let maximum = maximum.max(1);
        Arc::new(Self {
            maximum,
            idle_floor: if maximum_configured {
                maximum.min(5)
            } else {
                maximum.min(2)
            },
            state: Mutex::new(State {
                desired: maximum.min(5),
                running: 0,
                failures: 0,
                next_poll: Instant::now(),
            }),
            changed: Notify::new(),
        })
    }

    pub(crate) async fn acquire(self: &Arc<Self>) -> PollPermit {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let deadline = {
                let mut state = self.state.lock().unwrap();
                if state.running < state.desired && Instant::now() >= state.next_poll {
                    state.running += 1;
                    return PollPermit(self.clone());
                }
                (Instant::now() < state.next_poll).then_some(state.next_poll)
            };
            match deadline {
                Some(deadline) => {
                    tokio::select! { _ = notified => {}, _ = tokio::time::sleep_until(deadline) => {} }
                }
                None => notified.await,
            }
        }
    }

    pub(crate) fn report(&self, result: &Result<PollOutcome, PollError>, partial_responses: bool) {
        let mut state = self.state.lock().unwrap();
        match result {
            Ok(PollOutcome::Processed | PollOutcome::PartialFailure) => {
                state.failures = 0;
                state.desired = state.desired.saturating_add(1).min(self.maximum);
            }
            Ok(PollOutcome::Empty) => {
                // Never increase a concurrency level reduced by a recent rejection on an empty poll.
                state.desired = state.desired.min(self.idle_floor);
            }
            Err(PollError::FunctionFailed) if partial_responses => {}
            Err(_) => {
                state.desired = state.desired.div_ceil(2).max(1);
                state.failures = state.failures.saturating_add(1);
                let delay = Duration::from_millis(250)
                    .saturating_mul(1_u32 << state.failures.saturating_sub(1).min(5));
                state.next_poll = Instant::now() + delay;
            }
        }
        drop(state);
        self.changed.notify_waiters();
    }
}

pub(crate) struct PollPermit(Arc<PollingControl>);

impl Drop for PollPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.running = state.running.saturating_sub(1);
        }
        self.0.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::lambda::LambdaInternalError;

    #[tokio::test]
    async fn backlog_grows_polling_and_throttling_backs_off_without_clamping_to_rc() {
        let control = PollingControl::new(10, false);
        for _ in 0..5 {
            control.report(&Ok(PollOutcome::Processed), false);
        }
        assert_eq!(control.state.lock().unwrap().desired, 10);
        control.report(
            &Err(PollError::Invocation(LambdaInternalError::Throttled)),
            false,
        );
        assert_eq!(control.state.lock().unwrap().desired, 5);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), control.acquire())
                .await
                .is_err()
        );
        for _ in 0..3 {
            control.report(
                &Err(PollError::Invocation(LambdaInternalError::Throttled)),
                false,
            );
        }
        assert_eq!(control.state.lock().unwrap().desired, 1);
        let before = control.state.lock().unwrap().next_poll;
        control.report(&Err(PollError::FunctionFailed), true);
        assert_eq!(control.state.lock().unwrap().next_poll, before);
        control.report(&Ok(PollOutcome::Empty), false);
        assert_eq!(control.state.lock().unwrap().desired, 1);
        control.report(&Ok(PollOutcome::Processed), false);
        assert_eq!(control.state.lock().unwrap().desired, 2);
    }

    #[tokio::test]
    async fn maximum_and_cancellation_release_polling_slots() {
        let control = PollingControl::new(2, true);
        let a = control.acquire().await;
        let b = control.acquire().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), control.acquire())
                .await
                .is_err()
        );
        drop(a);
        let c = tokio::time::timeout(Duration::from_millis(50), control.acquire())
            .await
            .unwrap();
        assert_eq!(control.state.lock().unwrap().running, 2);
        drop((b, c));
        assert_eq!(control.state.lock().unwrap().running, 0);
    }
}
