//! Packet capture presentation: payload decoding, hex dumps, and per-second
//! rates for the Packet Capture screen. Payloads are the manager's base64
//! (Go `[]byte` JSON) and stay in memory only.

use crate::{
    clock,
    dashboard_wire::{Packet, PacketSnapshot},
};
use std::collections::BTreeMap;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with optional padding. None for anything malformed.
pub fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let value = value.trim_end_matches('=');
    if value.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in value.bytes() {
        let sextet = ALPHABET.iter().position(|&c| c == byte)? as u32;
        buffer = (buffer << 6) | sextet;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(value >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `45 00 00 4a 1c 46 …`, the first `count` bytes.
pub fn hex_preview(bytes: &[u8], count: usize) -> String {
    let mut preview = bytes
        .iter()
        .take(count)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > count {
        preview.push_str(" …");
    }
    preview
}

/// Offset, eight hex bytes, and printable ASCII per line.
pub fn hex_dump(bytes: &[u8], max_lines: usize) -> Vec<String> {
    bytes
        .chunks(8)
        .take(max_lines)
        .enumerate()
        .map(|(line, chunk)| {
            let hex = chunk
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {hex:<23}  {ascii}", line * 8)
        })
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureSummary {
    pub packets: usize,
    pub outbound: usize,
    pub denied: usize,
    pub bytes: u64,
    /// Span of the loaded packets, in milliseconds since the epoch.
    pub first: Option<i64>,
    pub last: Option<i64>,
}

pub fn summary(snapshot: &PacketSnapshot) -> CaptureSummary {
    let times: Vec<i64> = snapshot
        .packets
        .iter()
        .filter_map(|p| clock::parse_millis(&p.timestamp))
        .collect();
    CaptureSummary {
        packets: snapshot.packets.len(),
        // The recorder's direction is from the sandbox: "tx" leaves it.
        outbound: snapshot
            .packets
            .iter()
            .filter(|p| p.direction == "tx")
            .count(),
        denied: snapshot.packets.iter().filter(|p| !p.allowed).count(),
        bytes: snapshot
            .packets
            .iter()
            .map(|p| p.length.max(0) as u64)
            .sum(),
        first: times.iter().min().copied(),
        last: times.iter().max().copied(),
    }
}

/// Packets the desktop keeps for one capture: the recorder's own retention
/// (`packetcapture.DefaultMaxPackets`).
pub const KEEP: usize = 2048;

/// Fold a read taken after cursor `after` into what the desktop holds. Reads
/// continue the capture, so their packets are appended and the newest
/// [`KEEP`] kept. A sandbox restart brings a new recorder that numbers from 1
/// again; its `latest` then falls behind the cursor, and the desktop starts
/// over from the beginning.
pub fn merge(held: &mut PacketSnapshot, read: PacketSnapshot, after: u64) {
    held.active = read.active;
    held.latest = read.latest;
    held.oldest = read.oldest;
    held.evicted = read.evicted;
    if read.latest < after {
        held.packets.clear();
        held.next = 0;
        return;
    }
    held.packets
        .extend(read.packets.into_iter().filter(|p| p.sequence > after));
    let excess = held.packets.len().saturating_sub(KEEP);
    held.packets.drain(..excess);
    held.next = read.next.max(after);
}

/// Whether the recorder holds packets the desktop has not read yet.
pub fn behind(snapshot: &PacketSnapshot) -> bool {
    snapshot.next < snapshot.latest
}

/// Packets per second for one capture, kept apart from the frames so the
/// chart keeps its history after old frames leave the bounded buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureRate {
    /// Allowed and denied packets per second of manager time.
    seconds: BTreeMap<i64, (u32, u32)>,
    /// How far the desktop clock runs ahead of the manager's, in ms: the
    /// smallest gap seen between a read and the newest frame it returned.
    offset: Option<i64>,
}

impl CaptureRate {
    /// Seconds of history kept.
    pub const HISTORY: i64 = 600;

    /// Count frames read at `received` (desktop clock, ms). Pass each frame
    /// once, when it is first read.
    pub fn record<'a>(&mut self, packets: impl IntoIterator<Item = &'a Packet>, received: i64) {
        let mut newest = None;
        for packet in packets {
            let Some(time) = clock::parse_millis(&packet.timestamp) else {
                continue;
            };
            let bucket = self.seconds.entry(time.div_euclid(1000)).or_default();
            if packet.allowed {
                bucket.0 += 1;
            } else {
                bucket.1 += 1;
            }
            newest = newest.max(Some(time));
        }
        if let Some(newest) = newest {
            let gap = received - newest;
            self.offset = Some(self.offset.map_or(gap, |offset| offset.min(gap)));
        }
        if let Some(&last) = self.seconds.keys().next_back() {
            self.seconds = self.seconds.split_off(&(last - Self::HISTORY + 1));
        }
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn is_empty(&self) -> bool {
        self.seconds.is_empty()
    }

    /// Allowed and denied packets for the `seconds` ending at `now` (desktop
    /// clock, ms), oldest first, so a live chart scrolls through quiet
    /// seconds. `None` ends at the newest frame, for a capture that is paused
    /// or not read live.
    pub fn window(&self, seconds: usize, now: Option<i64>) -> Vec<(u32, u32)> {
        let end = match now {
            Some(now) => (now - self.offset.unwrap_or(0)).div_euclid(1000),
            None => match self.seconds.keys().next_back() {
                Some(&last) => last,
                None => return vec![(0, 0); seconds],
            },
        };
        (end - seconds as i64 + 1..=end)
            .map(|second| self.seconds.get(&second).copied().unwrap_or_default())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_rejects_garbage() {
        for bytes in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            &[0, 255, 16, 128, 7],
        ] {
            let encoded = encode_base64(bytes);
            assert_eq!(decode_base64(&encoded).as_deref(), Some(bytes), "{encoded}");
        }
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(decode_base64("RQAASg==").unwrap(), [0x45, 0, 0, 0x4a]);
        assert!(decode_base64("not base64!").is_none());
        assert!(decode_base64("A").is_none());
    }

    #[test]
    fn hex_views_are_bounded_and_printable() {
        let bytes = b"E\x00\x00J\x1cF@\x00GET / HTTP";
        assert_eq!(hex_preview(bytes, 4), "45 00 00 4a …");
        let dump = hex_dump(bytes, 1);
        assert_eq!(dump, ["0000  45 00 00 4a 1c 46 40 00  E..J.F@."]);
        assert_eq!(
            hex_dump(bytes, 8)[1],
            "0008  47 45 54 20 2f 20 48 54  GET / HT"
        );
    }

    #[test]
    fn summary_and_rates_count_direction_and_decision() {
        let packet = |ms: i64, direction: &str, allowed| Packet {
            timestamp: clock::format_millis(1_790_070_000_000 + ms),
            direction: direction.into(),
            allowed,
            length: 100,
            ..Default::default()
        };
        let snapshot = PacketSnapshot {
            packets: vec![
                packet(0, "tx", true),
                packet(300, "rx", true),
                packet(1_200, "tx", false),
                packet(2_900, "tx", true),
            ],
            ..Default::default()
        };
        let summary = summary(&snapshot);
        assert_eq!(
            (summary.packets, summary.outbound, summary.denied),
            (4, 3, 1)
        );
        assert_eq!(summary.bytes, 400);
        assert_eq!(summary.last.unwrap() - summary.first.unwrap(), 2_900);
    }

    #[test]
    fn packet_rates_outlive_the_frames_and_scroll_with_the_clock() {
        let packet = |ms: i64, allowed| Packet {
            timestamp: clock::format_millis(1_000_000_000_000 + ms),
            allowed,
            ..Default::default()
        };
        let base = 1_000_000_000_000_i64;
        let mut rate = CaptureRate::default();
        assert!(rate.is_empty());
        assert_eq!(rate.window(2, None), [(0, 0), (0, 0)]);
        // Read 200 ms after the newest frame: the desktop runs 200 ms ahead.
        rate.record(
            &[packet(0, true), packet(300, true), packet(1_200, false)],
            base + 1_400,
        );
        assert_eq!(rate.window(3, None), [(0, 0), (2, 0), (0, 1)]);
        // A later read adds to the counts; the frames themselves are gone.
        rate.record(&[packet(2_900, true)], base + 3_000);
        assert_eq!(rate.window(3, None), [(2, 0), (0, 1), (1, 0)]);
        // Live, the window ends at the desktop's now, less the offset, and
        // scrolls through quiet seconds.
        assert_eq!(rate.window(2, Some(base + 2_100)), [(0, 1), (1, 0)]);
        assert_eq!(rate.window(2, Some(base + 5_100)), [(0, 0), (0, 0)]);
        assert_eq!(
            rate.window(5, Some(base + 4_100)),
            [(2, 0), (0, 1), (1, 0), (0, 0), (0, 0)]
        );
        // History is bounded.
        rate.record(
            &[packet(CaptureRate::HISTORY * 1000, true)],
            base + CaptureRate::HISTORY * 1000,
        );
        assert_eq!(rate.seconds.len(), 3);
        rate.clear();
        assert!(rate.is_empty());
    }

    #[test]
    fn live_reads_append_trim_and_restart_with_the_recorder() {
        let packet = |sequence| Packet {
            sequence,
            ..Default::default()
        };
        let read = |from: u64, to: u64, latest| PacketSnapshot {
            active: true,
            packets: (from..=to).map(packet).collect(),
            next: to,
            latest,
            ..Default::default()
        };
        let mut held = read(1, 3, 5);
        assert!(behind(&held));
        merge(&mut held, read(4, 5, 5), 3);
        let sequences =
            |held: &PacketSnapshot| held.packets.iter().map(|p| p.sequence).collect::<Vec<_>>();
        assert_eq!(sequences(&held), [1, 2, 3, 4, 5]);
        assert_eq!(held.next, 5);
        assert!(!behind(&held));
        // Nothing new keeps the cursor; a stop is reported.
        let quiet = PacketSnapshot {
            active: false,
            next: 5,
            latest: 5,
            ..Default::default()
        };
        merge(&mut held, quiet, 5);
        assert_eq!((held.packets.len(), held.next, held.active), (5, 5, false));
        // Only the newest KEEP packets stay.
        let mut held = read(1, KEEP as u64, KEEP as u64 + 10);
        merge(
            &mut held,
            read(KEEP as u64 + 1, KEEP as u64 + 10, KEEP as u64 + 10),
            KEEP as u64,
        );
        assert_eq!(held.packets.len(), KEEP);
        assert_eq!(held.packets[0].sequence, 11);
        // A restarted sandbox numbers from 1 again: read from the start.
        merge(&mut held, read(1, 2, 2), KEEP as u64 + 10);
        assert!(held.packets.is_empty());
        assert_eq!((held.next, held.latest), (0, 2));
        assert!(behind(&held));
    }
}
