// SPDX-License-Identifier: Apache-2.0
//! Keeping the netmap stream alive: when the control server goes away the data plane
//! keeps running on the last netmap, and this loop redials with exponential backoff until a stream
//! delivers again. Dialing is injected, so the loop is tested without a server.

use flowmesh_proto::control::MapResponse;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An open netmap stream.
pub trait MessageStream: Send {
    /// `Ok(None)`: the server closed the stream.
    fn next(&mut self) -> BoxFut<'_, Result<Option<MapResponse>, String>>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlEvent {
    /// A (re)opened stream delivered its first message: the control server is reachable.
    Up,
    Map(Box<MapResponse>),
    /// The stream ended or could not be opened; the loop is about to wait and redial.
    Down(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub min: Duration,
    pub max: Duration,
    /// A stream silent this long is presumed dead and redialed. A server that vanished without
    /// closing (crash, container restart, NAT timeout) leaves a half-open connection that a
    /// read-only long poll would otherwise wait on forever (found by the soak rehearsal).
    pub idle: Duration,
    /// Bound on one dial (connect + Noise handshake + map request): a server that accepts TCP but
    /// never answers would otherwise hang the redial for good.
    pub dial: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            min: Duration::from_secs(1),
            max: Duration::from_secs(30),
            idle: Duration::from_secs(120),
            dial: Duration::from_secs(30),
        }
    }
}

/// Run until the receiver of `events` is dropped (the engine stopped). `initial` is the stream the
/// engine already opened for its first netmap; its first message has been consumed, so it counts as up.
pub async fn run<S, D, F>(
    initial: Option<S>,
    mut dial: D,
    events: mpsc::Sender<ControlEvent>,
    backoff: Backoff,
) where
    S: MessageStream,
    D: FnMut() -> F,
    F: Future<Output = Result<S, String>>,
{
    let mut delay = backoff.min;
    let mut current = initial;
    let mut fresh = false; // the initial stream was already announced by the caller
    loop {
        let stream = match current.take() {
            Some(s) => Ok(s),
            None => {
                fresh = true;
                tokio::time::timeout(backoff.dial, dial())
                    .await
                    .unwrap_or_else(|_| {
                        Err(format!(
                            "control server did not answer within {} s",
                            backoff.dial.as_secs()
                        ))
                    })
            }
        };
        let reason = match stream {
            Err(e) => e,
            Ok(mut s) => loop {
                let Ok(next) = tokio::time::timeout(backoff.idle, s.next()).await else {
                    break format!(
                        "no message from the control server for {} s; connection presumed dead",
                        backoff.idle.as_secs()
                    );
                };
                match next {
                    Ok(Some(m)) => {
                        if fresh {
                            fresh = false;
                            delay = backoff.min;
                            if events.send(ControlEvent::Up).await.is_err() {
                                return;
                            }
                        }
                        if events.send(ControlEvent::Map(Box::new(m))).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break "map stream closed".to_string(),
                    Err(e) => break e,
                }
            },
        };
        if events.send(ControlEvent::Down(reason)).await.is_err() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = events.closed() => return,
        }
        delay = (delay * 2).min(backoff.max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Yields its scripted items, then the given end.
    struct Script(VecDeque<Result<Option<MapResponse>, String>>);
    impl MessageStream for Script {
        fn next(&mut self) -> BoxFut<'_, Result<Option<MapResponse>, String>> {
            let item = self.0.pop_front().unwrap_or(Ok(None));
            Box::pin(async move { item })
        }
    }

    fn msg(domain: &str) -> Result<Option<MapResponse>, String> {
        Ok(Some(MapResponse {
            domain: domain.into(),
            ..Default::default()
        }))
    }

    fn short() -> Backoff {
        Backoff {
            min: Duration::from_millis(1),
            max: Duration::from_millis(4),
            ..Backoff::default()
        }
    }

    /// Collect events until `n` arrived, then stop the loop by dropping the receiver.
    async fn collect(mut rx: mpsc::Receiver<ControlEvent>, n: usize) -> Vec<ControlEvent> {
        let mut out = Vec::new();
        while out.len() < n {
            out.push(rx.recv().await.unwrap());
        }
        out
    }

    fn label(e: &ControlEvent) -> String {
        match e {
            ControlEvent::Up => "up".into(),
            ControlEvent::Map(m) => format!("map:{}", m.domain),
            ControlEvent::Down(r) => format!("down:{r}"),
        }
    }

    #[tokio::test]
    async fn reconnects_after_the_stream_closes() {
        let (tx, rx) = mpsc::channel(16);
        let dials = Arc::new(Mutex::new(VecDeque::from([
            Err("connection refused".to_string()),
            Ok(Script(VecDeque::from([msg("b1"), msg("b2")]))),
        ])));
        let d = dials.clone();
        let task = tokio::spawn(run(
            Some(Script(VecDeque::from([msg("a1")]))),
            move || {
                let next = d
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Err("no more".into()));
                async move { next }
            },
            tx,
            short(),
        ));
        let got: Vec<String> = collect(rx, 6).await.iter().map(label).collect();
        assert_eq!(
            got,
            [
                "map:a1", // the initial stream is already up: no Up event
                "down:map stream closed",
                "down:connection refused", // a failed dial
                "up",                      // the redial delivered
                "map:b1",
                "map:b2",
            ]
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn stream_errors_are_reported_with_their_reason() {
        let (tx, rx) = mpsc::channel(16);
        let task = tokio::spawn(run(
            Some(Script(VecDeque::from([
                Err("connection reset".to_string()),
            ]))),
            || async { Err::<Script, _>("unreachable".to_string()) },
            tx,
            short(),
        ));
        let got: Vec<String> = collect(rx, 3).await.iter().map(label).collect();
        assert_eq!(
            got,
            [
                "down:connection reset",
                "down:unreachable",
                "down:unreachable"
            ]
        );
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_doubles_to_the_cap_and_resets_after_success() {
        let times = Arc::new(Mutex::new(Vec::new()));
        let t = times.clone();
        let start = tokio::time::Instant::now();
        let count = Arc::new(Mutex::new(0u32));
        let c = count.clone();
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(run(
            None::<Script>,
            move || {
                t.lock().unwrap().push(start.elapsed());
                let mut n = c.lock().unwrap();
                *n += 1;
                // Dial 5 succeeds (and closes); every other dial fails.
                let r = if *n == 5 {
                    Ok(Script(VecDeque::from([msg("x")])))
                } else {
                    Err("refused".into())
                };
                async move { r }
            },
            tx,
            Backoff {
                min: Duration::from_secs(1),
                max: Duration::from_secs(4),
                ..Backoff::default()
            },
        ));
        // Dials 1-4 fail, 5 succeeds then closes, 6-7 fail: 4 + 3 (up, map, down) + 2 downs.
        let _ = collect(rx, 9).await;
        task.await.unwrap();
        let secs: Vec<u64> = times.lock().unwrap().iter().map(|d| d.as_secs()).collect();
        // Waits: 1, 2, 4, 4 (capped), then reset to 1 after the success, then 2.
        assert_eq!(secs, [0, 1, 3, 7, 11, 12, 14]);
    }

    #[tokio::test]
    async fn stops_when_the_engine_drops_the_receiver() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        // Would loop forever if it ignored the closed channel.
        tokio::time::timeout(
            Duration::from_secs(2),
            run(
                None::<Script>,
                || async { Err::<Script, _>("x".to_string()) },
                tx,
                Backoff::default(),
            ),
        )
        .await
        .unwrap();
    }

    /// Stays open but says nothing.
    struct Silent;
    impl MessageStream for Silent {
        fn next(&mut self) -> BoxFut<'_, Result<Option<MapResponse>, String>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_stream_is_presumed_dead() {
        let (tx, mut rx) = mpsc::channel(16);
        let start = tokio::time::Instant::now();
        let task = tokio::spawn(run(
            Some(Silent),
            || async { Err::<Silent, _>("still down".to_string()) },
            tx,
            Backoff::default(),
        ));
        let first = rx.recv().await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(120));
        assert_eq!(
            label(&first),
            "down:no message from the control server for 120 s; connection presumed dead"
        );
        drop(rx);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn messages_keep_the_stream_alive() {
        // A message every 100 s (under the 120 s limit) keeps one stream for good.
        struct Slow(u32);
        impl MessageStream for Slow {
            fn next(&mut self) -> BoxFut<'_, Result<Option<MapResponse>, String>> {
                self.0 += 1;
                let n = self.0;
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(100)).await;
                    msg(&n.to_string())
                })
            }
        }
        let (tx, rx) = mpsc::channel(16);
        let task = tokio::spawn(run(
            Some(Slow(0)),
            || async { Err::<Slow, _>("redialed".to_string()) },
            tx,
            Backoff::default(),
        ));
        let got: Vec<String> = collect(rx, 4).await.iter().map(label).collect();
        assert_eq!(got, ["map:1", "map:2", "map:3", "map:4"]);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_dial_that_never_answers_is_bounded() {
        let (tx, mut rx) = mpsc::channel(16);
        let start = tokio::time::Instant::now();
        let task = tokio::spawn(run(
            None::<Silent>,
            std::future::pending::<Result<Silent, String>>,
            tx,
            Backoff::default(),
        ));
        let first = rx.recv().await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(30));
        assert_eq!(
            label(&first),
            "down:control server did not answer within 30 s"
        );
        drop(rx);
        task.await.unwrap();
    }
}
