// SPDX-License-Identifier: Apache-2.0
//! Backend state (cli.md §1). The names are interoperability facts: the WanFlow gateway agent compares them literally.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BackendState {
    NeedsLogin,
    Stopped,
    Starting,
    Running,
}

impl BackendState {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendState::NeedsLogin => "NeedsLogin",
            BackendState::Stopped => "Stopped",
            BackendState::Starting => "Starting",
            BackendState::Running => "Running",
        }
    }
}

/// Inputs the state is derived from; nothing here is stored as "the state" itself, so it cannot drift.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts {
    /// The node key has been accepted by the control server at least once (persisted).
    pub logged_in: bool,
    /// The user wants the network up (`up` without a later `down`/`logout`; persisted).
    pub want_running: bool,
    /// The last engine run was refused by the control server.
    pub refused: bool,
    /// The current engine run has received a netmap.
    pub live: bool,
}

pub fn derive(f: Facts) -> BackendState {
    if f.refused {
        return BackendState::NeedsLogin;
    }
    if !f.want_running {
        return if f.logged_in {
            BackendState::Stopped
        } else {
            BackendState::NeedsLogin
        };
    }
    if f.live {
        BackendState::Running
    } else {
        BackendState::Starting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(logged_in: bool, want_running: bool, refused: bool, live: bool) -> Facts {
        Facts {
            logged_in,
            want_running,
            refused,
            live,
        }
    }

    #[test]
    fn transitions_observed_on_the_official_client() {
        // Running normally.
        assert_eq!(derive(f(true, true, false, true)), BackendState::Running);
        // After down.
        assert_eq!(derive(f(true, false, false, false)), BackendState::Stopped);
        // After logout.
        assert_eq!(
            derive(f(false, false, false, false)),
            BackendState::NeedsLogin
        );
    }

    #[test]
    fn starting_until_the_first_netmap() {
        assert_eq!(derive(f(false, true, false, false)), BackendState::Starting);
        assert_eq!(derive(f(true, true, false, false)), BackendState::Starting);
    }

    #[test]
    fn refusal_wins_over_everything() {
        assert_eq!(derive(f(true, true, true, true)), BackendState::NeedsLogin);
    }

    #[test]
    fn names_are_literal() {
        let all = [
            BackendState::NeedsLogin,
            BackendState::Stopped,
            BackendState::Starting,
            BackendState::Running,
        ];
        let names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, ["NeedsLogin", "Stopped", "Starting", "Running"]);
        for s in all {
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
    }
}
