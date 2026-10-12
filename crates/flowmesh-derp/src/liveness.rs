// SPDX-License-Identifier: Apache-2.0
//! Noticing a DERP connection that died without closing: after a quiet spell the client
//! pings the server (which echoes client pings, derp.md); no frame at all within the timeout means
//! the connection is dead. The server's own keepalives (every ~62 s) would take minutes to notice.

use std::time::Duration;

/// Ping when nothing has arrived for this long.
pub const IDLE: Duration = Duration::from_secs(15);
/// After a ping, any frame within this long counts as alive.
pub const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Quiet,
    SendPing,
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Liveness {
    last_rx: Duration,
    ping_sent: Option<Duration>,
}

impl Liveness {
    pub fn new(now: Duration) -> Self {
        Self {
            last_rx: now,
            ping_sent: None,
        }
    }

    /// Something arrived from the server.
    pub fn on_frame(&mut self, now: Duration) {
        self.last_rx = now;
        self.ping_sent = None;
    }

    pub fn tick(&mut self, now: Duration) -> Verdict {
        match self.ping_sent {
            Some(sent) if now.saturating_sub(sent) >= TIMEOUT => Verdict::Dead,
            Some(_) => Verdict::Quiet,
            None if now.saturating_sub(self.last_rx) >= IDLE => {
                self.ping_sent = Some(now);
                Verdict::SendPing
            }
            None => Verdict::Quiet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn busy_connections_are_never_pinged() {
        let mut l = Liveness::new(Duration::ZERO);
        for t in 1..100 {
            l.on_frame(t * S);
            assert_eq!(l.tick(t * S), Verdict::Quiet);
        }
    }

    #[test]
    fn quiet_connection_is_pinged_then_kept_by_any_frame() {
        let mut l = Liveness::new(Duration::ZERO);
        assert_eq!(l.tick(14 * S), Verdict::Quiet);
        assert_eq!(l.tick(15 * S), Verdict::SendPing);
        assert_eq!(l.tick(16 * S), Verdict::Quiet, "one ping at a time");
        l.on_frame(17 * S);
        assert_eq!(l.tick(19 * S), Verdict::Quiet);
        assert_eq!(
            l.tick(32 * S),
            Verdict::SendPing,
            "15 s after the last frame"
        );
    }

    #[test]
    fn no_answer_within_the_timeout_is_dead() {
        let mut l = Liveness::new(Duration::ZERO);
        assert_eq!(l.tick(15 * S), Verdict::SendPing);
        assert_eq!(l.tick(19 * S), Verdict::Quiet);
        assert_eq!(l.tick(20 * S), Verdict::Dead);
        assert_eq!(l.tick(21 * S), Verdict::Dead, "stays dead");
    }

    #[test]
    fn a_frame_after_the_ping_cancels_it() {
        let mut l = Liveness::new(Duration::ZERO);
        l.tick(15 * S);
        l.on_frame(19 * S);
        assert_eq!(l.tick(25 * S), Verdict::Quiet);
    }
}
