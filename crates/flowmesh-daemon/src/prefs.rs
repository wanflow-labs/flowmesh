// SPDX-License-Identifier: Apache-2.0
//! Preferences and the merge semantics of `up` / `set` (cli.md §1).
//!
//! There is deliberately **no default control server**: the first `up` must give `--login-server`
//! (zero-telemetry promise, design doc §7.4).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub control_url: String,
    pub hostname: String,
    /// Default true, same as the official client.
    pub accept_dns: bool,
    /// Default false, same as the official client on Linux.
    pub accept_routes: bool,
    pub advertise_routes: Vec<IpNet>,
    /// Masquerade traffic forwarded from the mesh into advertised subnets. Default true, same as the
    /// official client (`--snat-subnet-routes`).
    pub snat_subnet_routes: bool,
    /// ACL tags requested from the control server (`--advertise-tags`).
    pub advertise_tags: Vec<String>,
    /// Refuse all inbound connections (`--shields-up`). Default false.
    pub shields_up: bool,
    /// Offer to be an exit node (`--advertise-exit-node`): advertises 0.0.0.0/0 and ::/0.
    pub advertise_exit_node: bool,
    /// Only replies may be forwarded into the mesh (`--stateful-filtering`). Default false.
    pub stateful_filtering: bool,
    pub want_running: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            control_url: String::new(),
            hostname: String::new(),
            accept_dns: true,
            accept_routes: false,
            advertise_routes: Vec::new(),
            snat_subnet_routes: true,
            advertise_tags: Vec::new(),
            shields_up: false,
            advertise_exit_node: false,
            stateful_filtering: false,
            want_running: false,
        }
    }
}

/// Flags given explicitly on the command line (None = not given).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefsUpdate {
    pub control_url: Option<String>,
    pub hostname: Option<String>,
    pub accept_dns: Option<bool>,
    pub accept_routes: Option<bool>,
    pub advertise_routes: Option<Vec<IpNet>>,
    pub snat_subnet_routes: Option<bool>,
    pub advertise_tags: Option<Vec<String>>,
    pub shields_up: Option<bool>,
    pub advertise_exit_node: Option<bool>,
    pub stateful_filtering: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrefsError {
    /// Corresponds to the official rule: changing settings via `up` must mention all non-default flags.
    #[error(
        "changing settings via 'up' requires mentioning all non-default flags; re-run with --reset, or with: {suggestion}"
    )]
    MissingFlags {
        missing: Vec<&'static str>,
        suggestion: String,
    },
    #[error("--login-server is required (there is no default control server)")]
    NoControlUrl,
}

impl Prefs {
    /// Command-line flags for this configuration's non-default settings, in a fixed order.
    pub fn non_default_flags(&self) -> Vec<(&'static str, String)> {
        let d = Prefs::default();
        let mut out = Vec::new();
        if self.control_url != d.control_url {
            out.push(("--login-server", self.control_url.clone()));
        }
        if self.hostname != d.hostname {
            out.push(("--hostname", self.hostname.clone()));
        }
        if self.accept_dns != d.accept_dns {
            out.push(("--accept-dns", self.accept_dns.to_string()));
        }
        if self.accept_routes != d.accept_routes {
            out.push(("--accept-routes", self.accept_routes.to_string()));
        }
        if self.advertise_routes != d.advertise_routes {
            let joined: Vec<String> = self
                .advertise_routes
                .iter()
                .map(ToString::to_string)
                .collect();
            out.push(("--advertise-routes", joined.join(",")));
        }
        if self.snat_subnet_routes != d.snat_subnet_routes {
            out.push(("--snat-subnet-routes", self.snat_subnet_routes.to_string()));
        }
        if self.advertise_tags != d.advertise_tags {
            out.push(("--advertise-tags", self.advertise_tags.join(",")));
        }
        if self.shields_up != d.shields_up {
            out.push(("--shields-up", self.shields_up.to_string()));
        }
        if self.advertise_exit_node != d.advertise_exit_node {
            out.push((
                "--advertise-exit-node",
                self.advertise_exit_node.to_string(),
            ));
        }
        if self.stateful_filtering != d.stateful_filtering {
            out.push(("--stateful-filtering", self.stateful_filtering.to_string()));
        }
        out
    }

    /// `up`: merge an update. Without `reset`, every non-default setting must be mentioned in `update`.
    pub fn apply_up(&self, update: &PrefsUpdate, reset: bool) -> Result<Prefs, PrefsError> {
        let base = if reset {
            Prefs::default()
        } else {
            self.clone()
        };
        let mut merged = base.apply_set(update);
        if !reset {
            let missing: Vec<&'static str> = self
                .non_default_flags()
                .into_iter()
                .map(|(flag, _)| flag)
                .filter(|flag| !update.mentions(flag))
                .collect();
            if !missing.is_empty() {
                let mut suggestion = String::from("flowmesh up");
                for (flag, value) in merged.non_default_flags() {
                    suggestion.push_str(&format!(" {flag}={value}"));
                }
                return Err(PrefsError::MissingFlags {
                    missing,
                    suggestion,
                });
            }
        }
        if merged.control_url.is_empty() {
            return Err(PrefsError::NoControlUrl);
        }
        merged.want_running = true;
        Ok(merged)
    }

    /// `set`: change only the fields given.
    pub fn apply_set(&self, update: &PrefsUpdate) -> Prefs {
        let mut p = self.clone();
        if let Some(v) = &update.control_url {
            p.control_url.clone_from(v);
        }
        if let Some(v) = &update.hostname {
            p.hostname.clone_from(v);
        }
        if let Some(v) = update.accept_dns {
            p.accept_dns = v;
        }
        if let Some(v) = update.accept_routes {
            p.accept_routes = v;
        }
        if let Some(v) = &update.advertise_routes {
            p.advertise_routes.clone_from(v);
        }
        if let Some(v) = update.snat_subnet_routes {
            p.snat_subnet_routes = v;
        }
        if let Some(v) = &update.advertise_tags {
            p.advertise_tags.clone_from(v);
        }
        if let Some(v) = update.shields_up {
            p.shields_up = v;
        }
        if let Some(v) = update.advertise_exit_node {
            p.advertise_exit_node = v;
        }
        if let Some(v) = update.stateful_filtering {
            p.stateful_filtering = v;
        }
        p
    }
}

impl PrefsUpdate {
    /// Whether the flag (by its command-line name) was given.
    fn mentions(&self, flag: &str) -> bool {
        match flag {
            "--login-server" => self.control_url.is_some(),
            "--hostname" => self.hostname.is_some(),
            "--accept-dns" => self.accept_dns.is_some(),
            "--accept-routes" => self.accept_routes.is_some(),
            "--advertise-routes" => self.advertise_routes.is_some(),
            "--snat-subnet-routes" => self.snat_subnet_routes.is_some(),
            "--advertise-tags" => self.advertise_tags.is_some(),
            "--shields-up" => self.shields_up.is_some(),
            "--advertise-exit-node" => self.advertise_exit_node.is_some(),
            "--stateful-filtering" => self.stateful_filtering.is_some(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined() -> Prefs {
        Prefs::default()
            .apply_up(
                &PrefsUpdate {
                    control_url: Some("http://headscale.lab".into()),
                    hostname: Some("fm1".into()),
                    accept_dns: Some(false),
                    ..Default::default()
                },
                false,
            )
            .unwrap()
    }

    #[test]
    fn first_up_requires_control_url() {
        assert_eq!(
            Prefs::default().apply_up(&PrefsUpdate::default(), false),
            Err(PrefsError::NoControlUrl)
        );
    }

    #[test]
    fn first_up_with_flags_sets_prefs_and_want_running() {
        let p = joined();
        assert_eq!(p.control_url, "http://headscale.lab");
        assert_eq!(p.hostname, "fm1");
        assert!(!p.accept_dns);
        assert!(!p.accept_routes);
        assert!(p.want_running);
    }

    /// Same as observed on the official client: after down, a bare up is refused with the full suggested flag set.
    #[test]
    fn bare_up_after_join_is_refused_with_suggestion() {
        let mut p = joined();
        p.want_running = false;
        let err = p.apply_up(&PrefsUpdate::default(), false).unwrap_err();
        let PrefsError::MissingFlags {
            missing,
            suggestion,
        } = &err
        else {
            panic!("{err:?}")
        };
        assert_eq!(
            missing,
            &vec!["--login-server", "--hostname", "--accept-dns"]
        );
        assert_eq!(
            suggestion,
            "flowmesh up --login-server=http://headscale.lab --hostname=fm1 --accept-dns=false"
        );
    }

    #[test]
    fn up_mentioning_all_non_default_flags_is_accepted() {
        let mut p = joined();
        p.want_running = false;
        let again = p
            .apply_up(
                &PrefsUpdate {
                    control_url: Some("http://headscale.lab".into()),
                    hostname: Some("fm1".into()),
                    accept_dns: Some(false),
                    accept_routes: Some(true),
                    ..Default::default()
                },
                false,
            )
            .unwrap();
        assert!(again.want_running && again.accept_routes);
    }

    /// Every non-default flag counts as mentioned once it is given, whatever its value.
    #[test]
    fn each_flag_is_recognised_as_mentioned() {
        let p = Prefs {
            control_url: "http://h".into(),
            accept_routes: true,
            advertise_routes: vec!["10.0.0.0/24".parse().unwrap()],
            ..Default::default()
        };
        let all = PrefsUpdate {
            control_url: Some("http://h".into()),
            accept_routes: Some(true),
            advertise_routes: Some(vec!["10.0.0.0/24".parse().unwrap()]),
            ..Default::default()
        };
        assert!(p.apply_up(&all, false).is_ok());
        let drop_routes = PrefsUpdate {
            advertise_routes: None,
            ..all.clone()
        };
        let PrefsError::MissingFlags { missing, .. } = p.apply_up(&drop_routes, false).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(missing, vec!["--advertise-routes"]);
    }

    #[test]
    fn up_reset_restores_unmentioned_to_default() {
        let p = joined()
            .apply_up(
                &PrefsUpdate {
                    control_url: Some("http://other".into()),
                    ..Default::default()
                },
                true,
            )
            .unwrap();
        assert_eq!(p.control_url, "http://other");
        assert_eq!(p.hostname, "");
        assert!(
            p.accept_dns,
            "reset brings accept-dns back to the default true"
        );
    }

    #[test]
    fn set_changes_only_given_fields() {
        let p = joined();
        let q = p.apply_set(&PrefsUpdate {
            accept_routes: Some(true),
            ..Default::default()
        });
        assert_eq!(
            Prefs {
                accept_routes: true,
                ..p.clone()
            },
            q
        );
    }

    #[test]
    fn non_default_flags_order_and_values() {
        let p = Prefs {
            control_url: "http://h".into(),
            hostname: "n".into(),
            accept_dns: false,
            accept_routes: true,
            advertise_routes: vec![
                "10.0.0.0/24".parse().unwrap(),
                "10.1.0.0/24".parse().unwrap(),
            ],
            snat_subnet_routes: false,
            advertise_tags: Vec::new(),
            shields_up: false,
            advertise_exit_node: false,
            stateful_filtering: false,
            want_running: true,
        };
        assert_eq!(
            p.non_default_flags(),
            vec![
                ("--login-server", "http://h".to_string()),
                ("--hostname", "n".to_string()),
                ("--accept-dns", "false".to_string()),
                ("--accept-routes", "true".to_string()),
                ("--advertise-routes", "10.0.0.0/24,10.1.0.0/24".to_string()),
                ("--snat-subnet-routes", "false".to_string()),
            ]
        );
        assert!(Prefs::default().non_default_flags().is_empty());
    }

    #[test]
    fn prefs_roundtrip_json_with_missing_fields() {
        let p: Prefs = serde_json::from_str(r#"{"control_url":"http://h"}"#).unwrap();
        assert!(p.accept_dns, "missing fields take the default");
        assert_eq!(
            serde_json::from_str::<Prefs>(&serde_json::to_string(&joined()).unwrap()).unwrap(),
            joined()
        );
    }
}
