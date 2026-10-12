// SPDX-License-Identifier: Apache-2.0
//! Batched UDP I/O on the shared socket: one recvmmsg returns up to [`RECV_BATCH`] datagrams,
//! each possibly a GRO run of same-size segments, and datagrams to one destination leave in one
//! sendmsg with a UDP_SEGMENT (GSO) size when the kernel supports it. The socket options flowmesh
//! already relies on are left as they are (no path-MTU or don't-fragment changes).

// Only the Linux engine uses these; elsewhere the pure helpers exist for their tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ops::Range;

/// Datagrams per recvmmsg.
pub const RECV_BATCH: usize = 32;
/// Receive buffer per datagram: a GRO run can carry up to 64 KiB.
pub const RECV_BUF: usize = 65_535;
/// The kernel's limit on segments in one GSO send (UDP_MAX_SEGMENTS).
const GSO_MAX_SEGMENTS: usize = 64;
/// Largest UDP payload over IPv4; a GSO send is one datagram until the kernel splits it.
const GSO_MAX_BYTES: usize = 65_507;

/// The datagrams in `len` received bytes when GRO coalesced them with segment size `stride`
/// (stride 0 or ≥ len: one datagram). Every segment is `stride` long except possibly the last.
pub fn split_gro(len: usize, stride: usize) -> impl Iterator<Item = Range<usize>> {
    let step = if stride == 0 || stride >= len {
        len.max(1)
    } else {
        stride
    };
    (0..len)
        .step_by(step)
        .map(move |start| start..(start + step).min(len))
}

/// Groups of consecutive datagrams (by index into `sizes`) that can leave as one GSO send: all the
/// same size except a shorter last one, at most [`GSO_MAX_SEGMENTS`] and [`GSO_MAX_BYTES`].
pub fn gso_groups(sizes: &[usize]) -> Vec<Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    while start < sizes.len() {
        let seg = sizes[start];
        let mut end = start + 1;
        let mut bytes = seg;
        while end < sizes.len()
            && end - start < GSO_MAX_SEGMENTS
            && sizes[end] <= seg
            && sizes[end] > 0
            && bytes + sizes[end] <= GSO_MAX_BYTES
        {
            bytes += sizes[end];
            end += 1;
            if sizes[end - 1] < seg {
                break; // a shorter segment can only be the last one
            }
        }
        groups.push(start..end);
        start = end;
    }
    groups
}

#[cfg(target_os = "linux")]
pub use linux::{UdpRx, UdpTx, enable_gro};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage,
        recvmmsg, sendmsg, setsockopt, sockopt,
    };
    use std::collections::VecDeque;
    use std::io::{self, IoSlice, IoSliceMut};
    use std::net::{SocketAddr, SocketAddrV4};
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    /// Ask the kernel to coalesce received runs (UDP_GRO). Returns whether it accepted.
    pub fn enable_gro(sock: &UdpSocket) -> bool {
        setsockopt(sock, sockopt::UdpGroSegment, &true).is_ok()
    }

    /// Received datagrams not yet handed out, one recvmmsg at a time.
    pub struct UdpRx {
        bufs: Vec<Vec<u8>>,
        queue: VecDeque<(usize, Range<usize>, SocketAddr)>,
    }

    impl UdpRx {
        pub fn new() -> Self {
            Self {
                bufs: (0..RECV_BATCH).map(|_| vec![0u8; RECV_BUF]).collect(),
                queue: VecDeque::new(),
            }
        }

        /// Nothing received is waiting to be handed out.
        pub fn is_empty(&self) -> bool {
            self.queue.is_empty()
        }

        /// The next datagram and its source: from the last batch, or from a new recvmmsg.
        pub async fn next(&mut self, udp: &UdpSocket) -> io::Result<(&[u8], SocketAddr)> {
            loop {
                if let Some((i, r, from)) = self.queue.pop_front() {
                    return Ok((&self.bufs[i][r], from));
                }
                udp.readable().await?;
                let fd = udp.as_raw_fd();
                match udp.try_io(Interest::READABLE, || {
                    fill(fd, &mut self.bufs, &mut self.queue)
                }) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// One recvmmsg into `bufs`; queue every datagram (GRO runs split) with its source address.
    fn fill(
        fd: i32,
        bufs: &mut [Vec<u8>],
        queue: &mut VecDeque<(usize, Range<usize>, SocketAddr)>,
    ) -> io::Result<()> {
        // Headers are built per call: they hold raw pointers, so they can't live across an await
        // in a future that must be Send.
        let mut headers =
            MultiHeaders::<SockaddrStorage>::preallocate(bufs.len(), Some(nix::cmsg_space!(i32)));
        let mut iovs: Vec<[IoSliceMut<'_>; 1]> =
            bufs.iter_mut().map(|b| [IoSliceMut::new(b)]).collect();
        let results = recvmmsg(
            fd,
            &mut headers,
            iovs.iter_mut(),
            MsgFlags::MSG_DONTWAIT,
            None,
        )
        .map_err(io::Error::from)?;
        for (i, msg) in results.enumerate() {
            let Some(from) = msg.address.and_then(|a| socket_addr(&a)) else {
                continue;
            };
            let stride = msg
                .cmsgs()
                .into_iter()
                .flatten()
                .find_map(|c| match c {
                    ControlMessageOwned::UdpGroSegments(s) => usize::try_from(s).ok(),
                    _ => None,
                })
                .unwrap_or(0);
            for r in split_gro(msg.bytes, stride) {
                queue.push_back((i, r, from));
            }
        }
        Ok(())
    }

    fn socket_addr(a: &SockaddrStorage) -> Option<SocketAddr> {
        if let Some(v4) = a.as_sockaddr_in() {
            return Some(SocketAddr::V4(SocketAddrV4::new(v4.ip(), v4.port())));
        }
        a.as_sockaddr_in6().map(|v6| SocketAddr::V6((*v6).into()))
    }

    /// Batched sends: one GSO sendmsg per group of same-size datagrams to one destination, plain
    /// sends when GSO is unavailable (it is switched off for good after the kernel refuses it).
    pub struct UdpTx {
        gso: bool,
        joined: Vec<u8>,
    }

    impl UdpTx {
        pub fn new() -> Self {
            Self {
                gso: true,
                joined: Vec::with_capacity(GSO_MAX_BYTES),
            }
        }

        /// Send every datagram in `dgrams` to `dst`, in order. Errors are those a plain send_to
        /// would return; the caller handles them per destination.
        pub async fn send(
            &mut self,
            udp: &UdpSocket,
            dst: SocketAddr,
            dgrams: &[&[u8]],
        ) -> io::Result<()> {
            if !self.gso || dgrams.len() < 2 {
                for d in dgrams {
                    udp.send_to(d, dst).await?;
                }
                return Ok(());
            }
            let sizes: Vec<usize> = dgrams.iter().map(|d| d.len()).collect();
            for g in gso_groups(&sizes) {
                if g.len() == 1 {
                    udp.send_to(dgrams[g.start], dst).await?;
                    continue;
                }
                self.joined.clear();
                for d in &dgrams[g.clone()] {
                    self.joined.extend_from_slice(d);
                }
                match self
                    .send_gso(udp, dst, u16::try_from(sizes[g.start]).unwrap_or(u16::MAX))
                    .await
                {
                    Ok(()) => {}
                    // EIO: the device can't segment (no checksum offload); EINVAL: no UDP_SEGMENT.
                    Err(e)
                        if e.raw_os_error() == Some(nix::errno::Errno::EIO as i32)
                            || e.raw_os_error() == Some(nix::errno::Errno::EINVAL as i32) =>
                    {
                        self.gso = false;
                        for d in &dgrams[g] {
                            udp.send_to(d, dst).await?;
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }

        async fn send_gso(&self, udp: &UdpSocket, dst: SocketAddr, seg: u16) -> io::Result<()> {
            let SocketAddr::V4(v4) = dst else {
                return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
            };
            let addr = SockaddrIn::from(v4);
            let fd = udp.as_raw_fd();
            loop {
                udp.writable().await?;
                let r = udp.try_io(Interest::WRITABLE, || {
                    sendmsg(
                        fd,
                        &[IoSlice::new(&self.joined)],
                        &[ControlMessage::UdpGsoSegments(&seg)],
                        MsgFlags::MSG_DONTWAIT,
                        Some(&addr),
                    )
                    .map_err(io::Error::from)
                });
                match r {
                    Ok(_) => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gro_runs_split_into_strides_with_a_short_tail() {
        assert_eq!(
            split_gro(3000, 1000).collect::<Vec<_>>(),
            vec![0..1000, 1000..2000, 2000..3000]
        );
        assert_eq!(
            split_gro(2500, 1000).collect::<Vec<_>>(),
            vec![0..1000, 1000..2000, 2000..2500]
        );
        assert_eq!(split_gro(1000, 1000).collect::<Vec<_>>(), vec![0..1000]);
        assert_eq!(
            split_gro(700, 0).collect::<Vec<_>>(),
            vec![0..700],
            "no GRO: one datagram"
        );
        assert_eq!(split_gro(700, 1000).collect::<Vec<_>>(), vec![0..700]);
        assert_eq!(
            split_gro(0, 0).count(),
            0,
            "an empty datagram yields nothing"
        );
    }

    #[test]
    fn gso_groups_take_same_size_runs_and_a_shorter_last() {
        assert_eq!(gso_groups(&[]), Vec::<Range<usize>>::new());
        assert_eq!(gso_groups(&[100]), vec![0..1]);
        assert_eq!(gso_groups(&[100, 100, 100]), vec![0..3]);
        assert_eq!(
            gso_groups(&[100, 100, 60, 100]),
            vec![0..3, 3..4],
            "short one ends the group"
        );
        assert_eq!(
            gso_groups(&[100, 150, 150]),
            vec![0..1, 1..3],
            "a longer one starts a new group"
        );
        assert_eq!(gso_groups(&[100, 60, 60]), vec![0..2, 2..3]);
    }

    #[test]
    fn gso_groups_respect_kernel_limits() {
        // 64 segments at most.
        let small = vec![10; 130];
        assert_eq!(gso_groups(&small), vec![0..64, 64..128, 128..130]);
        // 65 507 bytes at most: 1360-byte segments fit 48 to a send (48 × 1360 = 65 280, 49 × 1360 = 66 640).
        let wg = vec![1360; 50];
        assert_eq!(gso_groups(&wg), vec![0..48, 48..50]);
    }
}
