// SPDX-License-Identifier: Apache-2.0
//! "Prefer relay" per-peer fallback: a pure, sans-IO state machine and the LAN-address predicate.
//!
//! In prefer-relay mode a peer normally goes through the relays (LAN direct is allowed). Only when the
//! relays stay silent for a peer that we are talking to does the peer fall back to ordinary direct
//! path discovery; once the relays have answered steadily for a while it returns to relay.
//!
//! All time comes from the caller as a monotonic [`Duration`], so scenarios replay with simulated time.
//! The caller feeds events in and acts on the answers; nothing here does I/O.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// A peer is "active" if anything was sent to or received from it less than this long ago (idle once
/// the window has fully elapsed).
pub const PREFER_ACTIVE_WINDOW: Duration = Duration::from_secs(15);
/// While a peer is active, probe it through the relays this often.
pub const PREFER_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// Relays count as dead (fallback may start) after this long without any relay pong.
pub const PREFER_RELAY_DEAD_AFTER: Duration = Duration::from_secs(15);
/// Shortest stay in fallback (debounce).
pub const PREFER_MIN_FALLBACK: Duration = Duration::from_secs(30);
/// Relays must have answered without a long gap for this long before leaving fallback.
pub const PREFER_RELAY_STABLE_FOR: Duration = Duration::from_secs(30);
/// Two relay pongs further apart than this break the streak (two probe intervals).
pub const PREFER_RELAY_MAX_GAP: Duration = Duration::from_secs(10);

/// Whether `ip` is a local-network address: 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7 and
/// fe80::/10 (an IPv4-mapped IPv6 address is judged as its IPv4 form). Everything else is not,
/// including 100.64.0.0/10 and the mesh's own fd7a:115c:a1e0::/48, which share address space with
/// the mesh addresses and must never be treated as "the same LAN".
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_lan_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_lan_v4(v4),
            None => {
                let s = v6.segments();
                if s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0 {
                    return false;
                }
                s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfe80
            }
        },
    }
}

fn is_lan_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

/// What a call to [`PreferFallback::update`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    NoChange,
    /// The peer just fell back to direct path discovery.
    Entered,
    /// The peer just returned to relay-only (plus LAN direct).
    Exited,
}

/// Per-peer prefer-relay state. The zero value means: never active, online, no relay pong seen,
/// not in fallback.
///
/// Rules (evaluated only while the peer is active, i.e. `now - last_active < PREFER_ACTIVE_WINDOW`;
/// an idle peer keeps whatever state it has and is neither probed nor judged):
///
/// * enter fallback = not in fallback, online, and
///   `now - max(last relay pong, start of this active period, online-since) >= PREFER_RELAY_DEAD_AFTER`;
/// * leave fallback = in fallback, `now - entered >= PREFER_MIN_FALLBACK`,
///   `now - start of relay-pong streak >= PREFER_RELAY_STABLE_FOR` and
///   `now - last relay pong <= PREFER_RELAY_MAX_GAP`.
///
/// "Start of this active period" is the moment the peer became active after being idle for longer
/// than the active window, so a relay pong from long ago cannot put a fresh flow straight into
/// fallback. A relay pong starts a new streak when it follows the previous one by more than
/// `PREFER_RELAY_MAX_GAP`.
#[derive(Default)]
pub(crate) struct PreferFallback {
    last_active: Option<Duration>,
    active_since: Option<Duration>,
    offline: bool,
    online_since: Option<Duration>,
    last_pong: Option<Duration>,
    streak_start: Option<Duration>,
    last_probe: Option<Duration>,
    fallback_since: Option<Duration>,
}

impl PreferFallback {
    /// Something was sent to or received from the peer (any path, data or disco).
    pub(crate) fn note_active(&mut self, now: Duration) {
        if !self.active_at(now) {
            self.active_since = Some(now);
        }
        self.last_active = Some(now);
    }

    /// The control plane's view of the peer. Going from offline to online restarts the relay clock;
    /// repeated calls with the same value change nothing.
    pub(crate) fn set_online(&mut self, now: Duration, online: bool) {
        if online && self.offline {
            self.online_since = Some(now);
        }
        self.offline = !online;
    }

    /// A disco pong arrived through a relay (cloud or peer relay).
    pub(crate) fn note_relay_pong(&mut self, now: Duration) {
        let continues = self
            .last_pong
            .is_some_and(|p| now.saturating_sub(p) <= PREFER_RELAY_MAX_GAP);
        if !continues {
            self.streak_start = Some(now);
        }
        self.last_pong = Some(now);
    }

    /// Whether a relay probe is due: only while active, at most once per probe interval.
    pub(crate) fn want_probe(&self, now: Duration) -> bool {
        self.active_at(now)
            && self
                .last_probe
                .is_none_or(|p| now.saturating_sub(p) >= PREFER_PROBE_INTERVAL)
    }

    /// A relay probe was sent.
    pub(crate) fn note_probe_sent(&mut self, now: Duration) {
        self.last_probe = Some(now);
    }

    /// Re-evaluates the peer; call it regularly (about once a second) while the peer may be active.
    pub(crate) fn update(&mut self, now: Duration) -> Transition {
        if !self.active_at(now) {
            return Transition::NoChange;
        }
        match self.fallback_since {
            None => {
                if self.offline {
                    return Transition::NoChange;
                }
                let since = [self.last_pong, self.active_since, self.online_since]
                    .into_iter()
                    .flatten()
                    .max()
                    .unwrap_or_default();
                if now.saturating_sub(since) >= PREFER_RELAY_DEAD_AFTER {
                    self.fallback_since = Some(now);
                    return Transition::Entered;
                }
            }
            Some(entered) => {
                let stable = self
                    .streak_start
                    .is_some_and(|s| now.saturating_sub(s) >= PREFER_RELAY_STABLE_FOR);
                let recent = self
                    .last_pong
                    .is_some_and(|p| now.saturating_sub(p) <= PREFER_RELAY_MAX_GAP);
                if now.saturating_sub(entered) >= PREFER_MIN_FALLBACK && stable && recent {
                    self.fallback_since = None;
                    return Transition::Exited;
                }
            }
        }
        Transition::NoChange
    }

    pub(crate) fn in_fallback(&self) -> bool {
        self.fallback_since.is_some()
    }

    fn active_at(&self, now: Duration) -> bool {
        self.last_active
            .is_some_and(|a| now.saturating_sub(a) < PREFER_ACTIVE_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::Transition::{Entered, Exited};
    use super::*;
    use std::collections::BTreeMap;

    fn secs(t: u64) -> Duration {
        Duration::from_secs(t)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test vector parses")
    }

    #[test]
    fn lan_vectors_true() {
        for s in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_lan(ip(s)), "{s} should be LAN");
        }
    }

    #[test]
    fn lan_vectors_false() {
        for s in [
            "172.32.0.1",
            "100.64.0.1",
            "100.100.100.100",
            "8.8.8.8",
            "fd7a:115c:a1e0::1",
            "2001:db8::1",
            "::1",
            "127.0.0.1",
        ] {
            assert!(!is_lan(ip(s)), "{s} should not be LAN");
        }
    }

    #[test]
    fn lan_boundaries() {
        for s in [
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "11.0.0.0",
            "9.255.255.255",
            "fbff::1",
            "fe00::1",
            "fec0::1",
            "::ffff:8.8.8.8",
            "fd7a:115c:a1e1::1",
        ] {
            let want = s == "fd7a:115c:a1e1::1";
            assert_eq!(is_lan(ip(s)), want, "{s}");
        }
        for s in [
            "fc00::1",
            "fdff::1",
            "febf::1",
            "::ffff:10.1.2.3",
            "::ffff:172.16.0.1",
            "::ffff:169.254.0.1",
        ] {
            assert!(is_lan(ip(s)), "{s} should be LAN");
        }
    }

    /// Per-second record of a simulated timeline.
    struct Trace {
        fb: BTreeMap<u64, bool>,
        probe: BTreeMap<u64, bool>,
        transitions: Vec<(u64, Transition)>,
    }

    impl Trace {
        fn fb(&self, t: u64) -> bool {
            self.fb[&t]
        }
        fn probe(&self, t: u64) -> bool {
            self.probe[&t]
        }
    }

    /// Replays ticks (one per listed second): at each second the scenario feeds its events, then the probe loop
    /// asks `want_probe` (and records a send when it says yes), then `update` runs.
    fn run(
        fb: &mut PreferFallback,
        ticks: impl IntoIterator<Item = u64>,
        mut events: impl FnMut(&mut PreferFallback, u64),
    ) -> Trace {
        let mut tr = Trace {
            fb: BTreeMap::new(),
            probe: BTreeMap::new(),
            transitions: Vec::new(),
        };
        for t in ticks {
            events(fb, t);
            let want = fb.want_probe(secs(t));
            if want {
                fb.note_probe_sent(secs(t));
            }
            tr.probe.insert(t, want);
            let tx = fb.update(secs(t));
            if tx != Transition::NoChange {
                tr.transitions.push((t, tx));
            }
            tr.fb.insert(t, fb.in_fallback());
        }
        tr
    }

    #[test]
    fn s1_no_activity() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=100, |_, _| {});
        for t in 0..=100 {
            assert!(!tr.probe(t), "probe@{t}");
        }
        assert!(!tr.fb(100));
        assert!(tr.transitions.is_empty());
    }

    #[test]
    fn s2_active_with_regular_pongs() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=60, |fb, t| {
            fb.note_active(secs(t));
            if t % 5 == 0 {
                fb.note_relay_pong(secs(t));
            }
        });
        for t in 0..=60 {
            assert!(!tr.fb(t), "fb@{t}");
        }
        assert!(tr.transitions.is_empty());
    }

    /// S3 events: active every second 0..=20, no pong.
    fn s3_events(fb: &mut PreferFallback, t: u64) {
        if t <= 20 {
            fb.note_active(secs(t));
        }
    }

    #[test]
    fn s3_relay_silent_enters_fallback() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=20, s3_events);
        assert!(!tr.fb(14));
        assert!(tr.fb(15));
        assert_eq!(tr.transitions, vec![(15, Entered)]);
    }

    #[test]
    fn s4_old_pong_does_not_hurry_a_new_flow() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=120, |fb, t| {
            if t == 0 {
                fb.note_relay_pong(secs(0));
            }
            if t == 0 || (100..=120).contains(&t) {
                fb.note_active(secs(t));
            }
        });
        assert!(!tr.fb(114));
        assert!(tr.fb(115));
        assert_eq!(tr.transitions, vec![(115, Entered)]);
    }

    #[test]
    fn s5_offline_then_online_restarts_the_clock() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=60, |fb, t| {
            if t == 0 {
                fb.set_online(secs(0), false);
            }
            if t == 30 {
                fb.set_online(secs(30), true);
            }
            fb.note_active(secs(t));
        });
        assert!(!tr.fb(29));
        assert!(!tr.fb(44));
        assert!(tr.fb(45));
        assert_eq!(tr.transitions, vec![(45, Entered)]);
    }

    #[test]
    fn s6_receive_only_side_probes_and_falls_back() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=15, |fb, t| fb.note_active(secs(t)));
        assert!(tr.probe(0));
        assert!(!tr.probe(3));
        assert!(tr.probe(5));
        assert!(tr.fb(15));
    }

    /// Runs a timeline 0..=`end` for the post-fallback scenarios (S7, S8, S10): `active(t)` and `pongs(t)`
    /// say which seconds carry activity and a relay pong. With no pong before 20 each of them enters
    /// fallback at 15, as in S3.
    fn after_fallback(
        end: u64,
        active: impl Fn(u64) -> bool,
        pongs: impl Fn(u64) -> bool,
    ) -> Trace {
        let mut fb = PreferFallback::default();
        run(&mut fb, 0..=end, |fb, t| {
            if active(t) {
                fb.note_active(secs(t));
            }
            if pongs(t) {
                fb.note_relay_pong(secs(t));
            }
        })
    }

    #[test]
    fn s7_exit_needs_thirty_seconds_of_steady_pongs() {
        let tr = after_fallback(60, |_| true, |t| (20..=60).contains(&t) && t % 5 == 0);
        assert!(tr.fb(15));
        assert!(tr.fb(45));
        assert!(tr.fb(49));
        assert!(!tr.fb(50));
        assert_eq!(tr.transitions, vec![(15, Entered), (50, Exited)]);
    }

    #[test]
    fn s8_a_gap_over_ten_seconds_restarts_the_streak() {
        let tr = after_fallback(
            80,
            |_| true,
            |t| t == 20 || t == 25 || ((40..=80).contains(&t) && t % 5 == 0),
        );
        assert!(tr.fb(50));
        assert!(tr.fb(69));
        assert!(!tr.fb(70));
        assert_eq!(tr.transitions, vec![(15, Entered), (70, Exited)]);
    }

    #[test]
    fn s9_fallback_holds_while_idle_then_resumes_judging() {
        let mut fb = PreferFallback::default();
        let tr = run(&mut fb, 0..=140, |fb, t| {
            if t <= 16 || (100..=140).contains(&t) {
                fb.note_active(secs(t));
            }
            if (100..=140).contains(&t) && t % 5 == 0 {
                fb.note_relay_pong(secs(t));
            }
        });
        assert!(tr.fb(99));
        assert!(tr.fb(129));
        assert!(!tr.fb(130));
        assert_eq!(tr.transitions, vec![(15, Entered), (130, Exited)]);
    }

    #[test]
    fn s10_a_single_pong_does_not_leave_fallback() {
        let tr = after_fallback(60, |t| t <= 60, |t| t == 20);
        assert!(tr.fb(60));
        assert_eq!(tr.transitions, vec![(15, Entered)]);
    }
}
