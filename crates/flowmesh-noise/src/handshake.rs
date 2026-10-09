// SPDX-License-Identifier: Apache-2.0
//! 发起方握手（control.md §4）。

use crate::Error;
use crate::frame::{self, Frame, FrameType};
use crate::transport::Transport;
use flowmesh_proto::key::{MachinePrivate, MachinePublic};

/// Noise 参数（control.md §4）。
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// 握手 prologue，与协议版本绑定（control.md §4）。
pub fn prologue(version: u16) -> Vec<u8> {
    format!("Tailscale Control Protocol v{version}").into_bytes()
}

pub struct Initiator {
    state: snow::HandshakeState,
}

impl Initiator {
    /// 返回发起方状态，以及要放进 `X-Tailscale-Handshake` 头的完整发起消息
    /// （2 字节大端版本 + 类型 1 的帧）。
    pub fn new(
        machine: &MachinePrivate,
        server: &MachinePublic,
        version: u16,
    ) -> Result<(Self, Vec<u8>), Error> {
        let mut state = snow::Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(machine.as_bytes())
            .remote_public_key(&server.0)
            .prologue(&prologue(version))
            .build_initiator()?;
        let mut buf = vec![0u8; frame::MAX_FRAME_PAYLOAD];
        let n = state.write_message(&[], &mut buf)?;
        let mut msg = version.to_be_bytes().to_vec();
        msg.extend(frame::encode(FrameType::Initiation, &buf[..n])?);
        Ok((Self { state }, msg))
    }

    /// 处理服务端的响应帧，得到加密记录层。
    pub fn finish(mut self, response: Frame) -> Result<Transport, Error> {
        if response.ty != FrameType::Response {
            return Err(Error::UnexpectedFrame(response.ty));
        }
        let mut scratch = vec![0u8; response.payload.len()];
        self.state.read_message(&response.payload, &mut scratch)?;
        if !self.state.is_handshake_finished() {
            return Err(Error::Protocol("handshake not finished after response"));
        }
        // 发起方：split 的第一把密钥用于发送，第二把用于接收。
        let (send, recv) = self.state.dangerously_get_raw_split();
        Ok(Transport::from_raw_split(send, recv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameDecoder, encode};

    struct Responder {
        state: snow::HandshakeState,
    }

    fn responder(server: &MachinePrivate, prologue_bytes: &[u8]) -> Responder {
        let state = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(server.as_bytes())
            .prologue(prologue_bytes)
            .build_responder()
            .unwrap();
        Responder { state }
    }

    /// 按观测到的格式拆开发起消息：2 字节版本 + 帧。
    fn split_initiation(msg: &[u8]) -> (u16, Frame) {
        let version = u16::from_be_bytes([msg[0], msg[1]]);
        let mut dec = FrameDecoder::default();
        dec.push(&msg[2..]);
        (version, dec.next_frame().unwrap().unwrap())
    }

    /// 响应方的记录层：split 的两把密钥方向与发起方相反。
    fn responder_transport(r: &mut Responder) -> Transport {
        let (i2r, r2i) = r.state.dangerously_get_raw_split();
        Transport::from_raw_split(r2i, i2r)
    }

    fn keys() -> (MachinePrivate, MachinePrivate) {
        (
            MachinePrivate::generate().unwrap(),
            MachinePrivate::generate().unwrap(),
        )
    }

    #[test]
    fn initiation_matches_observed_layout() {
        let (client, server) = keys();
        let (_, msg) = Initiator::new(&client, &server.public(), 131).unwrap();
        // 观测值：总长 101，前 5 字节 00 83 01 00 60（framing-summary.json）。
        assert_eq!(msg.len(), 101);
        assert_eq!(&msg[..5], &[0x00, 0x83, 0x01, 0x00, 0x60]);
    }

    #[test]
    fn full_handshake_and_records_both_directions() {
        let (client, server) = keys();
        let (init, msg) = Initiator::new(&client, &server.public(), 131).unwrap();
        let (version, frame) = split_initiation(&msg);
        assert_eq!(version, 131);
        assert_eq!(frame.ty, FrameType::Initiation);

        let mut r = responder(&server, &prologue(131));
        let mut scratch = [0u8; 1024];
        r.state.read_message(&frame.payload, &mut scratch).unwrap();
        // 响应方确认对端静态公钥就是客户端的 machine key。
        assert_eq!(
            r.state.get_remote_static().unwrap(),
            client.public().0.as_slice()
        );
        let n = r.state.write_message(&[], &mut scratch).unwrap();
        assert_eq!(n, 48, "observed response payload length");
        let response = Frame {
            ty: FrameType::Response,
            payload: scratch[..n].to_vec(),
        };

        let mut client_t = init.finish(response).unwrap();
        let mut server_t = responder_transport(&mut r);

        // 客户端 → 服务端：超过单帧上限的明文必须被切成多帧。
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let wire = client_t.seal(&big).unwrap();
        let mut dec = FrameDecoder::default();
        dec.push(&wire);
        let mut got = Vec::new();
        let mut frames = 0;
        while let Some(f) = dec.next_frame().unwrap() {
            assert_eq!(f.ty, FrameType::Record);
            got.extend_from_slice(&server_t.open(f).unwrap());
            frames += 1;
        }
        assert_eq!(got, big);
        assert_eq!(frames, 3);

        // 服务端 → 客户端，连续多条，覆盖 nonce 递增。
        for msg in [&b"hello"[..], b"world", b"third"] {
            let wire = server_t.seal(msg).unwrap();
            let mut dec = FrameDecoder::default();
            dec.push(&wire);
            let f = dec.next_frame().unwrap().unwrap();
            assert_eq!(client_t.open(f).unwrap(), msg);
        }
    }

    #[test]
    fn responder_with_different_prologue_rejects_initiation() {
        let (client, server) = keys();
        let (_, msg) = Initiator::new(&client, &server.public(), 131).unwrap();
        let (_, frame) = split_initiation(&msg);
        let mut r = responder(&server, &prologue(130));
        let mut scratch = [0u8; 1024];
        assert!(r.state.read_message(&frame.payload, &mut scratch).is_err());
    }

    #[test]
    fn finish_rejects_non_response_frame() {
        let (client, server) = keys();
        let (init, _) = Initiator::new(&client, &server.public(), 131).unwrap();
        let bogus = Frame {
            ty: FrameType::Record,
            payload: vec![0; 48],
        };
        assert!(matches!(
            init.finish(bogus),
            Err(Error::UnexpectedFrame(FrameType::Record))
        ));
    }

    #[test]
    fn open_rejects_non_record_frame_and_tampering() {
        let (client, server) = keys();
        let (init, msg) = Initiator::new(&client, &server.public(), 131).unwrap();
        let (_, frame) = split_initiation(&msg);
        let mut r = responder(&server, &prologue(131));
        let mut scratch = [0u8; 1024];
        r.state.read_message(&frame.payload, &mut scratch).unwrap();
        let n = r.state.write_message(&[], &mut scratch).unwrap();
        let mut client_t = init
            .finish(Frame {
                ty: FrameType::Response,
                payload: scratch[..n].to_vec(),
            })
            .unwrap();
        let mut server_t = responder_transport(&mut r);

        let wrong = Frame {
            ty: FrameType::Initiation,
            payload: vec![],
        };
        assert!(matches!(
            client_t.open(wrong),
            Err(Error::UnexpectedFrame(FrameType::Initiation))
        ));

        let wire = server_t.seal(b"data").unwrap();
        let mut dec = FrameDecoder::default();
        dec.push(&wire);
        let mut f = dec.next_frame().unwrap().unwrap();
        f.payload[0] ^= 1;
        assert!(matches!(client_t.open(f), Err(Error::Decrypt)));
        let _ = encode;
    }
}
