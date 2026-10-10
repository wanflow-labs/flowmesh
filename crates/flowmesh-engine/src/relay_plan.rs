// SPDX-License-Identifier: Apache-2.0
//! Which DERP regions to (re)connect and which one is home (design §7.2), sans-IO: the event loop
//! reports connection outcomes and the time, and carries out the returned actions. Connecting never
//! happens inline, so a dead relay cannot stall the loop.

use flowmesh_proto::derp::DerpMap;
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

/// First retry delay for a region that failed to connect; doubles per failure up to `RETRY_MAX`.
pub const RETRY_MIN: Duration = Duration::from_secs(1);
pub const RETRY_MAX: Duration = Duration::from_secs(30);
/// How long home may stay unreachable before another region becomes home.
pub const HOME_FAILOVER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAction {
    /// Start connecting to this region in the background.
    Connect(u32),
    /// This region is home from now on: tell peers (control server) and the relay.
    SetHome(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPlan {
    home: u32,
    connected: BTreeSet<u32>,
    connecting: BTreeSet<u32>,
    /// Region → (earliest next attempt, delay after the next failure).
    retry: HashMap<u32, (Duration, Duration)>,
    home_down_since: Option<Duration>,
}

impl RelayPlan {
    /// `home` was chosen at start-up and is already connected.
    pub fn new(home: u32) -> Self {
        Self {
            home,
            connected: BTreeSet::from([home]),
            connecting: BTreeSet::new(),
            retry: HashMap::new(),
            home_down_since: None,
        }
    }

    pub fn home(&self) -> u32 {
        self.home
    }

    pub fn is_connected(&self, region: u32) -> bool {
        self.connected.contains(&region)
    }

    /// Something wants to send via `region`: true if it can go now; otherwise a connection is
    /// started when allowed (the packet is dropped meanwhile, as on a lossy path).
    pub fn want(&mut self, region: u32, now: Duration) -> (bool, Vec<RelayAction>) {
        if self.connected.contains(&region) {
            return (true, Vec::new());
        }
        (false, self.connect_if_due(region, now))
    }

    fn connect_if_due(&mut self, region: u32, now: Duration) -> Vec<RelayAction> {
        if self.connected.contains(&region) {
            return Vec::new();
        }
        let due = self.retry.get(&region).is_none_or(|(at, _)| now >= *at);
        if due && self.connecting.insert(region) {
            vec![RelayAction::Connect(region)]
        } else {
            Vec::new()
        }
    }

    pub fn on_connected(&mut self, region: u32) {
        self.connecting.remove(&region);
        self.connected.insert(region);
        self.retry.remove(&region);
        if region == self.home {
            self.home_down_since = None;
        }
    }

    pub fn on_failed(&mut self, region: u32, now: Duration) {
        self.connecting.remove(&region);
        let delay = self.retry.get(&region).map_or(RETRY_MIN, |(_, d)| *d);
        self.retry
            .insert(region, (now + delay, (delay * 2).min(RETRY_MAX)));
        if region == self.home {
            self.home_down_since.get_or_insert(now);
        }
    }

    /// An established connection ended. Home is redialed at once.
    pub fn on_closed(&mut self, region: u32, now: Duration) -> Vec<RelayAction> {
        self.connected.remove(&region);
        if region != self.home {
            return Vec::new();
        }
        self.home_down_since.get_or_insert(now);
        self.connect_if_due(region, now)
    }

    /// Periodic driver: keep redialing home, and fail over when home has been down too long.
    pub fn tick(&mut self, now: Duration, dm: &DerpMap) -> Vec<RelayAction> {
        if self.connected.contains(&self.home) {
            return Vec::new();
        }
        let down_for = self
            .home_down_since
            .map_or(Duration::ZERO, |t| now.saturating_sub(t));
        if down_for >= HOME_FAILOVER {
            if let Some(next) = self.next_home(dm, now) {
                self.home = next;
                self.home_down_since = (!self.connected.contains(&next)).then_some(now);
                let mut acts = vec![RelayAction::SetHome(next)];
                acts.extend(self.connect_if_due(next, now));
                return acts;
            }
        }
        self.connect_if_due(self.home, now)
    }

    /// Another region that may be home: an already connected one first, else the lowest-numbered
    /// eligible region that is not waiting out a retry delay.
    fn next_home(&self, dm: &DerpMap, now: Duration) -> Option<u32> {
        let eligible: Vec<u32> = dm
            .regions
            .iter()
            .filter(|(id, r)| {
                **id != self.home && !r.no_measure_no_home && r.nodes.iter().any(|n| !n.stun_only)
            })
            .map(|(id, _)| *id)
            .collect();
        eligible
            .iter()
            .find(|id| self.connected.contains(id))
            .or_else(|| {
                eligible
                    .iter()
                    .find(|id| self.retry.get(id).is_none_or(|(at, _)| now >= *at))
            })
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::derp::{DerpNode, DerpRegion};

    const S: Duration = Duration::from_secs(1);

    fn dm(regions: &[(u32, bool, bool)]) -> DerpMap {
        DerpMap {
            regions: regions
                .iter()
                .map(|&(id, no_home, stun_only)| {
                    (
                        id,
                        DerpRegion {
                            region_id: id,
                            no_measure_no_home: no_home,
                            nodes: vec![DerpNode {
                                stun_only,
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    )
                })
                .collect(),
            ..Default::default()
        }
    }

    fn two() -> DerpMap {
        dm(&[(1000, false, false), (1001, false, false)])
    }

    #[test]
    fn home_is_redialed_at_once_after_it_closes() {
        let mut p = RelayPlan::new(1000);
        assert!(p.is_connected(1000));
        assert_eq!(p.on_closed(1000, 5 * S), vec![RelayAction::Connect(1000)]);
        assert!(!p.is_connected(1000));
        // Already connecting: no duplicate attempt from ticks or sends.
        assert!(p.tick(6 * S, &two()).is_empty());
        assert_eq!(p.want(1000, 6 * S), (false, vec![]));
        p.on_connected(1000);
        assert_eq!(p.want(1000, 7 * S), (true, vec![]));
        assert!(p.tick(8 * S, &two()).is_empty());
    }

    #[test]
    fn other_regions_connect_on_demand_and_are_not_redialed_on_close() {
        let mut p = RelayPlan::new(1000);
        assert_eq!(p.want(1001, S), (false, vec![RelayAction::Connect(1001)]));
        p.on_connected(1001);
        assert_eq!(p.want(1001, 2 * S), (true, vec![]));
        assert!(p.on_closed(1001, 3 * S).is_empty());
        assert!(
            p.tick(4 * S, &two()).is_empty(),
            "home is fine; nothing to do"
        );
        assert_eq!(
            p.want(1001, 4 * S),
            (false, vec![RelayAction::Connect(1001)]),
            "next send redials"
        );
    }

    #[test]
    fn failures_back_off_per_region() {
        let mut p = RelayPlan::new(1000);
        assert_eq!(p.want(1001, 10 * S).1, vec![RelayAction::Connect(1001)]);
        p.on_failed(1001, 10 * S);
        assert!(p.want(1001, 10 * S + S / 2).1.is_empty(), "waiting 1 s");
        assert_eq!(p.want(1001, 11 * S).1, vec![RelayAction::Connect(1001)]);
        p.on_failed(1001, 11 * S);
        assert!(p.want(1001, 12 * S).1.is_empty(), "waiting 2 s");
        assert_eq!(p.want(1001, 13 * S).1, vec![RelayAction::Connect(1001)]);
        p.on_connected(1001);
        assert!(p.on_closed(1001, 14 * S).is_empty());
        assert_eq!(
            p.want(1001, 14 * S).1,
            vec![RelayAction::Connect(1001)],
            "success resets the delay"
        );
    }

    #[test]
    fn backoff_caps() {
        let mut p = RelayPlan::new(1000);
        let mut t = Duration::ZERO;
        let mut waits = Vec::new();
        for _ in 0..8 {
            // Find the first instant an attempt is allowed, second by second.
            let start = t;
            while p.want(1001, t).1.is_empty() {
                t += S;
            }
            waits.push((t - start).as_secs());
            p.on_failed(1001, t);
        }
        assert_eq!(waits, [0, 1, 2, 4, 8, 16, 30, 30]);
    }

    #[test]
    fn home_fails_over_after_ten_seconds_and_stays() {
        let mut p = RelayPlan::new(1000);
        let map = two();
        assert_eq!(p.on_closed(1000, 100 * S), vec![RelayAction::Connect(1000)]);
        p.on_failed(1000, 101 * S);
        assert!(p.tick(101 * S, &map).is_empty(), "retry not due yet");
        assert_eq!(p.tick(102 * S, &map), vec![RelayAction::Connect(1000)]);
        p.on_failed(1000, 102 * S);
        assert!(
            p.tick(109 * S, &map)
                .iter()
                .all(|a| *a == RelayAction::Connect(1000))
        );
        assert_eq!(p.home(), 1000, "9 s down: not yet");
        p.on_failed(1000, 109 * S);
        assert_eq!(
            p.tick(110 * S, &map),
            vec![RelayAction::SetHome(1001), RelayAction::Connect(1001)]
        );
        assert_eq!(p.home(), 1001);
        p.on_connected(1001);
        assert!(p.tick(111 * S, &map).is_empty());
        // The old home coming back does not move home back (no flapping).
        p.on_connected(1000);
        assert_eq!(p.home(), 1001);
    }

    #[test]
    fn failover_prefers_a_region_already_connected() {
        let mut p = RelayPlan::new(1000);
        let map = dm(&[
            (1000, false, false),
            (1001, false, false),
            (1002, false, false),
        ]);
        p.want(1002, S);
        p.on_connected(1002);
        p.on_closed(1000, 10 * S);
        p.on_failed(1000, 10 * S);
        assert_eq!(
            p.tick(20 * S, &map),
            vec![RelayAction::SetHome(1002)],
            "connected: nothing to dial"
        );
        assert!(p.tick(21 * S, &map).is_empty());
    }

    #[test]
    fn failover_skips_ineligible_and_backing_off_regions() {
        let mut p = RelayPlan::new(1000);
        let map = dm(&[
            (1000, false, false),
            (1001, true, false),
            (1002, false, true),
            (1003, false, false),
            (1004, false, false),
        ]);
        p.want(1003, S);
        p.on_failed(1003, 19 * S); // 1003 waits until 20 s
        p.on_closed(1000, 9 * S);
        p.on_failed(1000, 9 * S);
        let acts = p.tick(19 * S, &map);
        assert_eq!(
            acts,
            vec![RelayAction::SetHome(1004), RelayAction::Connect(1004)]
        );
    }

    #[test]
    fn no_other_region_keeps_redialing_home() {
        let mut p = RelayPlan::new(1000);
        let only = dm(&[(1000, false, false)]);
        p.on_closed(1000, Duration::ZERO);
        p.on_failed(1000, Duration::ZERO);
        assert_eq!(p.tick(60 * S, &only), vec![RelayAction::Connect(1000)]);
        assert_eq!(p.home(), 1000);
    }

    #[test]
    fn failover_to_an_unreachable_region_can_fail_over_again() {
        let mut p = RelayPlan::new(1000);
        let map = dm(&[(1000, false, false), (1001, false, false)]);
        p.on_closed(1000, Duration::ZERO);
        p.on_failed(1000, Duration::ZERO);
        assert_eq!(
            p.tick(10 * S, &map),
            vec![RelayAction::SetHome(1001), RelayAction::Connect(1001)]
        );
        p.on_failed(1001, 10 * S);
        // 1001 down for 10 s as well: back to 1000 if it can be tried.
        assert_eq!(
            p.tick(20 * S, &map),
            vec![RelayAction::SetHome(1000), RelayAction::Connect(1000)]
        );
    }

    /// A home that came back must not carry its old outage into the next one.
    #[test]
    fn reconnecting_home_clears_its_outage_clock() {
        let mut p = RelayPlan::new(1000);
        let map = two();
        p.on_closed(1000, Duration::ZERO);
        p.on_connected(1000);
        assert_eq!(p.on_closed(1000, 100 * S), vec![RelayAction::Connect(1000)]);
        p.on_failed(1000, 100 * S);
        assert_eq!(
            p.tick(101 * S, &map),
            vec![RelayAction::Connect(1000)],
            "redial first, no instant failover"
        );
        assert_eq!(p.home(), 1000);
    }

    /// Moving home onto a region that is already connected starts with a clean outage clock.
    #[test]
    fn failover_onto_a_connected_region_starts_clean() {
        let mut p = RelayPlan::new(1000);
        let map = two();
        p.want(1001, Duration::ZERO);
        p.on_connected(1001);
        p.on_closed(1000, Duration::ZERO);
        p.on_failed(1000, Duration::ZERO);
        assert_eq!(p.tick(10 * S, &map), vec![RelayAction::SetHome(1001)]);
        // Much later the new home drops: redial it before considering another failover.
        assert_eq!(p.on_closed(1001, 100 * S), vec![RelayAction::Connect(1001)]);
        p.on_failed(1001, 100 * S);
        assert_eq!(p.tick(101 * S, &map), vec![RelayAction::Connect(1001)]);
        assert_eq!(p.home(), 1001);
    }
}
