//! Throughput derived on the client from the manager's cumulative per-sandbox
//! byte counters. The manager reports totals only; rates and their history are
//! computed between refreshes, live only in this window, and restart whenever
//! the connection changes or a counter resets.

use crate::dashboard_wire::Sandbox;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Three minutes of history at the three-second refresh interval.
pub const SAMPLES: usize = 60;
/// Refreshes closer together than this say nothing reliable about a rate.
const MIN_INTERVAL: Duration = Duration::from_millis(500);

/// Bytes per second. Download is what the sandbox received (`rx_bytes`),
/// upload what it sent (`tx_bytes`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rate {
    pub down: f64,
    pub up: f64,
}

#[derive(Default)]
struct Series {
    baseline: Option<(Instant, u64, u64)>,
    rates: Vec<Rate>,
}

#[derive(Default)]
pub struct Throughput {
    series: HashMap<String, Series>,
}

impl Throughput {
    /// Record one refresh. Only running sandboxes whose traffic the manager
    /// reports are tracked; anything else forgets its history.
    pub fn record(&mut self, now: Instant, sandboxes: &[Sandbox]) {
        self.series
            .retain(|name, _| sandboxes.iter().any(|s| &s.name == name && tracked(s)));
        for sandbox in sandboxes.iter().filter(|s| tracked(s)) {
            let series = self.series.entry(sandbox.name.clone()).or_default();
            let (tx, rx) = (sandbox.tx_bytes, sandbox.rx_bytes);
            match series.baseline {
                Some((then, last_tx, last_rx)) if tx >= last_tx && rx >= last_rx => {
                    let elapsed = now.saturating_duration_since(then);
                    if elapsed < MIN_INTERVAL {
                        continue;
                    }
                    let seconds = elapsed.as_secs_f64();
                    series.rates.push(Rate {
                        down: (rx - last_rx) as f64 / seconds,
                        up: (tx - last_tx) as f64 / seconds,
                    });
                    if series.rates.len() > SAMPLES {
                        series.rates.remove(0);
                    }
                }
                // A smaller total means the counter restarted (for example the
                // sandbox rebooted); earlier samples are not comparable.
                Some(_) => series.rates.clear(),
                None => {}
            }
            series.baseline = Some((now, tx, rx));
        }
    }

    pub fn clear(&mut self) {
        self.series.clear();
    }

    /// Oldest first. Empty until two refreshes have been observed.
    pub fn rates(&self, name: &str) -> &[Rate] {
        self.series
            .get(name)
            .map(|series| series.rates.as_slice())
            .unwrap_or_default()
    }

    pub fn latest(&self, name: &str) -> Option<Rate> {
        self.rates(name).last().copied()
    }

    pub fn peak(&self, name: &str) -> Rate {
        self.rates(name)
            .iter()
            .fold(Rate::default(), |peak, rate| Rate {
                down: peak.down.max(rate.down),
                up: peak.up.max(rate.up),
            })
    }

    /// Clearly synthetic history for demo mode, which never polls a manager.
    pub fn demo(sandboxes: &[Sandbox]) -> Self {
        let mut throughput = Self::default();
        for (index, sandbox) in sandboxes.iter().filter(|s| tracked(s)).enumerate() {
            let seed = index as f64 * 1.7 + 0.4;
            let scale = [1_250_000.0, 86_000.0, 412_000.0, 3_000.0][index % 4];
            let rates = (0..SAMPLES)
                .map(|i| {
                    let t = i as f64 / (SAMPLES - 1) as f64;
                    let wave = 0.55 * (6.1 * t + seed).sin()
                        + 0.30 * (15.3 * t + 2.1 * seed).sin()
                        + 0.15 * (33.0 * t + 0.7 * seed).sin();
                    let burst = 0.9 * (-(t - 0.8).powi(2) / 0.004).exp();
                    let level = (0.45 + 0.4 * wave + burst).max(0.05);
                    Rate {
                        down: scale * level,
                        up: scale * 0.07 * (0.6 + 0.5 * (9.0 * t + seed).sin().abs()),
                    }
                })
                .collect();
            throughput.series.insert(
                sandbox.name.clone(),
                Series {
                    baseline: None,
                    rates,
                },
            );
        }
        throughput
    }
}

fn tracked(sandbox: &Sandbox) -> bool {
    sandbox.state == "running" && sandbox.traffic_available
}

/// Decimal units, as network rates are usually quoted.
pub fn rate_label(bytes_per_second: f64) -> String {
    format!("{}/s", scaled(bytes_per_second))
}

pub fn bytes_label(bytes: u64) -> String {
    scaled(bytes as f64)
}

/// `15262` → `15,262`.
pub fn count_label(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn scaled(value: f64) -> String {
    let value = value.max(0.0);
    for (unit, size) in [("GB", 1e9), ("MB", 1e6), ("kB", 1e3)] {
        if value >= size {
            let scaled = value / size;
            return if scaled < 10.0 {
                format!("{scaled:.1} {unit}")
            } else {
                format!("{scaled:.0} {unit}")
            };
        }
    }
    format!("{value:.0} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(name: &str, tx: u64, rx: u64) -> Sandbox {
        Sandbox {
            name: name.into(),
            state: "running".into(),
            traffic_available: true,
            tx_bytes: tx,
            rx_bytes: rx,
            ..Default::default()
        }
    }

    #[test]
    fn rates_are_deltas_over_elapsed_time() {
        let start = Instant::now();
        let mut throughput = Throughput::default();
        throughput.record(start, &[sandbox("dev", 1_000, 10_000)]);
        assert!(throughput.rates("dev").is_empty());
        throughput.record(
            start + Duration::from_secs(2),
            &[sandbox("dev", 3_000, 16_000)],
        );
        assert_eq!(
            throughput.latest("dev"),
            Some(Rate {
                down: 3_000.0,
                up: 1_000.0
            })
        );
        // A duplicate refresh neither adds a sample nor moves the baseline.
        throughput.record(
            start + Duration::from_millis(2_100),
            &[sandbox("dev", 9_000, 90_000)],
        );
        assert_eq!(throughput.rates("dev").len(), 1);
        throughput.record(
            start + Duration::from_secs(5),
            &[sandbox("dev", 3_000, 19_000)],
        );
        assert_eq!(throughput.latest("dev").unwrap().down, 1_000.0);
        assert_eq!(throughput.peak("dev").down, 3_000.0);
    }

    #[test]
    fn resets_stopped_and_untracked_sandboxes_forget_history() {
        let start = Instant::now();
        let at = |s| start + Duration::from_secs(s);
        let mut throughput = Throughput::default();
        throughput.record(at(0), &[sandbox("dev", 100, 100), sandbox("web", 0, 0)]);
        throughput.record(at(3), &[sandbox("dev", 400, 400), sandbox("web", 30, 30)]);
        assert_eq!(throughput.rates("dev").len(), 1);
        // The counter restarted: the old baseline cannot produce a rate.
        throughput.record(at(6), &[sandbox("dev", 10, 10), sandbox("web", 60, 60)]);
        assert!(throughput.rates("dev").is_empty());
        let mut stopped = sandbox("web", 60, 60);
        stopped.state = "stopped".into();
        let mut unreported = sandbox("dev", 20, 20);
        unreported.traffic_available = false;
        throughput.record(at(9), &[unreported, stopped]);
        assert!(throughput.rates("web").is_empty());
        assert!(throughput.latest("dev").is_none());
        throughput.record(at(12), &[sandbox("web", 90, 90)]);
        assert!(throughput.rates("web").is_empty(), "history restarts");
    }

    #[test]
    fn history_is_bounded() {
        let start = Instant::now();
        let mut throughput = Throughput::default();
        for i in 0..(SAMPLES as u64 + 20) {
            throughput.record(
                start + Duration::from_secs(3 * i),
                &[sandbox("dev", i * 10, i * 30)],
            );
        }
        assert_eq!(throughput.rates("dev").len(), SAMPLES);
        assert!(Throughput::demo(&[sandbox("dev", 0, 0)]).rates("dev").len() == SAMPLES);
    }

    #[test]
    fn labels_use_decimal_units() {
        assert_eq!(rate_label(0.0), "0 B/s");
        assert_eq!(rate_label(812.4), "812 B/s");
        assert_eq!(rate_label(86_000.0), "86 kB/s");
        assert_eq!(rate_label(1_240_000.0), "1.2 MB/s");
        assert_eq!(bytes_label(18_200_000), "18 MB");
        assert_eq!(bytes_label(3_400_000), "3.4 MB");
        assert_eq!(bytes_label(986_000), "986 kB");
        assert_eq!(bytes_label(1_310_000_000), "1.3 GB");
        assert_eq!(count_label(0), "0");
        assert_eq!(count_label(999), "999");
        assert_eq!(count_label(15_262), "15,262");
        assert_eq!(count_label(1_234_567), "1,234,567");
    }
}
