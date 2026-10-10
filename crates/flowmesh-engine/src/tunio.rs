// SPDX-License-Identifier: Apache-2.0
//! Batched TUN I/O (M11). With offload (IFF_VNET_HDR + TUNSETOFFLOAD) one read can return a TCP or
//! UDP super-packet that tun-rs splits into MTU-sized packets, and the packets written in one batch
//! are coalesced back (GRO) where possible; every read and write then carries a virtio header,
//! which this module hides. Without offload it reads and writes one packet at a time, as before.

use std::collections::VecDeque;
use std::io;
use tun_rs::{AsyncDevice, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

/// Room for one packet split out of a super-packet (≤ MTU), with headroom to spare.
const PACKET_BUF: usize = 4096;
/// Headroom in front of each written packet for the virtio header.
const HEADROOM: usize = VIRTIO_NET_HDR_LEN;

pub struct TunIo {
    dev: AsyncDevice,
    offload: bool,
    /// Raw read: virtio header + a super-packet.
    original: Vec<u8>,
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    /// Indices into `bufs` of packets read and not yet handed out.
    queue: VecDeque<usize>,
    /// Packets queued for writing, each `HEADROOM` bytes in; `out[..out_len]` are in use.
    out: Vec<Vec<u8>>,
    out_len: usize,
    gro: GROTable,
}

impl TunIo {
    pub fn new(dev: AsyncDevice) -> Self {
        let offload = dev.tcp_gso();
        let n = if offload { IDEAL_BATCH_SIZE } else { 1 };
        Self {
            dev,
            offload,
            original: vec![
                0u8;
                if offload {
                    VIRTIO_NET_HDR_LEN + 65_535
                } else {
                    0
                }
            ],
            bufs: (0..n).map(|_| vec![0u8; PACKET_BUF]).collect(),
            sizes: vec![0; n],
            queue: VecDeque::with_capacity(n),
            out: Vec::new(),
            out_len: 0,
            gro: GROTable::default(),
        }
    }

    pub fn offload(&self) -> bool {
        self.offload
    }

    /// Nothing read is waiting to be handed out.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The next packet from the TUN: from the last read, or from a new one. A read the offload code
    /// can't parse is logged and skipped; an error from the device itself is returned.
    pub async fn next(&mut self) -> io::Result<&[u8]> {
        loop {
            if let Some(i) = self.queue.pop_front() {
                return Ok(&self.bufs[i][..self.sizes[i]]);
            }
            match self
                .dev
                .recv_multiple(&mut self.original, &mut self.bufs, &mut self.sizes, 0)
                .await
            {
                Ok(n) => self.queue.extend(0..n),
                Err(e) if e.raw_os_error().is_none() => {
                    crate::linux::log(format!("tun read skipped: {e}"));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Packets queued for the next `flush`.
    pub fn queued(&self) -> usize {
        self.out_len
    }

    /// Queue a packet for the next `flush`.
    pub fn queue(&mut self, pkt: &[u8]) {
        if self.out_len == self.out.len() {
            self.out.push(Vec::with_capacity(HEADROOM + PACKET_BUF));
        }
        let b = &mut self.out[self.out_len];
        b.clear();
        b.resize(HEADROOM, 0);
        b.extend_from_slice(pkt);
        self.out_len += 1;
    }

    /// Write the queued packets, coalesced where offload allows.
    pub async fn flush(&mut self) -> io::Result<()> {
        if self.out_len == 0 {
            return Ok(());
        }
        let n = std::mem::replace(&mut self.out_len, 0);
        self.dev
            .send_multiple(&mut self.gro, &mut self.out[..n], HEADROOM)
            .await
            .map(|_| ())
    }
}
