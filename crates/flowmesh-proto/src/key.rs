// SPDX-License-Identifier: Apache-2.0
//! Curve25519 密钥及其文本形式。
//!
//! 公钥文本形式为 `<前缀>:<64 位小写十六进制>`，前缀区分用途
//! （docs/protocol/control.md §1；machine 密钥前缀 `mkey:` 已观测）。

use std::fmt;
use std::str::FromStr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("expected prefix {expected:?}")]
    WrongPrefix { expected: &'static str },
    #[error("key must be 64 hex characters")]
    BadLength,
    #[error("key is not valid hex")]
    BadHex,
    #[error("system random source failed")]
    Random,
}

macro_rules! public_key {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn is_zero(&self) -> bool {
                self.0 == [0u8; 32]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", Self::PREFIX, hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }

        impl FromStr for $name {
            type Err = KeyError;
            fn from_str(s: &str) -> Result<Self, KeyError> {
                let body = s.strip_prefix(Self::PREFIX).ok_or(KeyError::WrongPrefix {
                    expected: Self::PREFIX,
                })?;
                Ok(Self(decode_hex32(body)?))
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

public_key!(
    MachinePublic,
    "mkey:",
    "设备（machine）公钥，用于控制通道 Noise 握手。"
);
public_key!(
    NodePublic,
    "nodekey:",
    "节点公钥，即该节点的 WireGuard 公钥。"
);
public_key!(
    DiscoPublic,
    "discokey:",
    "disco 公钥，用于对端之间的路径探测消息。"
);

macro_rules! private_key {
    ($name:ident, $public:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// 用系统随机源生成新私钥。
            pub fn generate() -> Result<Self, KeyError> {
                let mut b = [0u8; 32];
                getrandom::fill(&mut b).map_err(|_| KeyError::Random)?;
                Ok(Self(b))
            }

            pub fn from_bytes(b: [u8; 32]) -> Self {
                Self(b)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn public(&self) -> $public {
                let secret = x25519_dalek::StaticSecret::from(self.0);
                $public(x25519_dalek::PublicKey::from(&secret).to_bytes())
            }

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            pub fn from_hex(s: &str) -> Result<Self, KeyError> {
                Ok(Self(decode_hex32(s)?))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

private_key!(MachinePrivate, MachinePublic, "设备私钥。");
private_key!(NodePrivate, NodePublic, "节点私钥。");
private_key!(DiscoPrivate, DiscoPublic, "disco 私钥。");

fn decode_hex32(s: &str) -> Result<[u8; 32], KeyError> {
    if s.len() != 64 {
        return Err(KeyError::BadLength);
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| KeyError::BadHex)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_text_roundtrip() {
        let text = format!("nodekey:{}", "ab".repeat(32));
        let k: NodePublic = text.parse().unwrap();
        assert_eq!(k.0, [0xab; 32]);
        assert_eq!(k.to_string(), text);
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let text = format!("mkey:{}", "ab".repeat(32));
        assert_eq!(
            text.parse::<NodePublic>(),
            Err(KeyError::WrongPrefix {
                expected: "nodekey:"
            })
        );
    }

    #[test]
    fn wrong_length_and_bad_hex_are_rejected() {
        assert_eq!(
            "discokey:abcd".parse::<DiscoPublic>(),
            Err(KeyError::BadLength)
        );
        let bad = format!("discokey:{}", "zz".repeat(32));
        assert_eq!(bad.parse::<DiscoPublic>(), Err(KeyError::BadHex));
    }

    #[test]
    fn zero_key() {
        let z: MachinePublic = format!("mkey:{}", "0".repeat(64)).parse().unwrap();
        assert!(z.is_zero());
        assert!(!MachinePublic([1; 32]).is_zero());
    }

    #[test]
    fn serde_uses_text_form() {
        let k = DiscoPublic([0x0f; 32]);
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, format!("\"discokey:{}\"", "0f".repeat(32)));
        assert_eq!(serde_json::from_str::<DiscoPublic>(&json).unwrap(), k);
    }

    #[test]
    fn private_debug_is_redacted() {
        let p = NodePrivate::from_bytes([0x5a; 32]);
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("5a5a"), "{dbg}");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn private_hex_roundtrip_and_public_derivation_is_stable() {
        let p = MachinePrivate::generate().unwrap();
        let q = MachinePrivate::from_hex(&p.to_hex()).unwrap();
        assert_eq!(p, q);
        assert_eq!(p.public(), q.public());
        assert_ne!(p.public(), MachinePrivate::generate().unwrap().public());
    }

    /// RFC 7748 §6.1 测试向量：Alice 的私钥对应的公钥。
    #[test]
    fn public_derivation_matches_rfc7748() {
        let mut sk = [0u8; 32];
        hex::decode_to_slice(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            &mut sk,
        )
        .unwrap();
        let pk = NodePrivate::from_bytes(sk).public();
        assert_eq!(
            hex::encode(pk.0),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }
}
