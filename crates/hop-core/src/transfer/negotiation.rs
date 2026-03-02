//! Session parameter negotiation for hop/1 connections.

use std::time::Instant;

use crate::proto::{DEFAULT_ZSTD_LEVEL, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};

/// Compression algorithm in use for a session.
#[derive(Debug, Clone)]
pub enum Compression {
    Zstd { level: i32 },
}

/// Parameters negotiated between sender and receiver for a transfer session.
#[derive(Debug, Clone)]
pub struct NegotiatedParams {
    pub compression: Option<Compression>,
    pub max_chunk_size: usize,
}

impl NegotiatedParams {
    /// Legacy parameters for hop/0 connections (no compression, 64 KiB chunks).
    pub fn legacy() -> Self {
        Self {
            compression: None,
            max_chunk_size: MIN_CHUNK_SIZE,
        }
    }

    /// Default v1 parameters (zstd compression, 1 MiB max chunk).
    pub fn v1_default() -> Self {
        Self {
            compression: Some(Compression::Zstd {
                level: DEFAULT_ZSTD_LEVEL,
            }),
            max_chunk_size: MAX_CHUNK_SIZE,
        }
    }

    /// Build from negotiated message values.
    pub fn from_negotiated(
        compression: Option<&str>,
        chunk_size: u32,
        zstd_level: Option<i32>,
    ) -> Self {
        let comp = match compression {
            Some("zstd") => Some(Compression::Zstd {
                level: zstd_level.unwrap_or(DEFAULT_ZSTD_LEVEL),
            }),
            _ => None,
        };
        Self {
            compression: comp,
            max_chunk_size: (chunk_size as usize).clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE),
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.compression.is_some()
    }

    pub fn zstd_level(&self) -> i32 {
        match &self.compression {
            Some(Compression::Zstd { level }) => *level,
            None => DEFAULT_ZSTD_LEVEL,
        }
    }
}

/// Adaptive chunk sizer — adjusts chunk size based on observed throughput.
pub struct ChunkSizer {
    current_size: usize,
    min_size: usize,
    max_size: usize,
    bytes_since_check: u64,
    last_check: Instant,
}

impl ChunkSizer {
    pub fn new(max_size: usize) -> Self {
        Self {
            current_size: MIN_CHUNK_SIZE,
            min_size: MIN_CHUNK_SIZE,
            max_size: max_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE),
            bytes_since_check: 0,
            last_check: Instant::now(),
        }
    }

    /// Return the current chunk size to use.
    pub fn chunk_size(&self) -> usize {
        self.current_size
    }

    /// Record bytes sent and potentially adjust chunk size.
    /// Called after each chunk is sent.
    pub fn record(&mut self, bytes: u64) {
        self.bytes_since_check += bytes;

        // Re-evaluate every 2 MiB
        if self.bytes_since_check >= 2 * 1024 * 1024 {
            let elapsed = self.last_check.elapsed();
            let secs = elapsed.as_secs_f64();
            if secs > 0.0 {
                let throughput_mbps = (self.bytes_since_check as f64) / secs / (1024.0 * 1024.0);
                // Scale chunk size proportionally to throughput
                // At 10 MB/s use 128 KiB, at 100 MB/s use 1 MiB
                let target = ((throughput_mbps / 10.0) * (128.0 * 1024.0)) as usize;
                self.current_size = target.clamp(self.min_size, self.max_size);
            }
            self.bytes_since_check = 0;
            self.last_check = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_params() {
        let p = NegotiatedParams::legacy();
        assert!(!p.is_compressed());
        assert_eq!(p.max_chunk_size, MIN_CHUNK_SIZE);
    }

    #[test]
    fn v1_default_params() {
        let p = NegotiatedParams::v1_default();
        assert!(p.is_compressed());
        assert_eq!(p.max_chunk_size, MAX_CHUNK_SIZE);
        assert_eq!(p.zstd_level(), DEFAULT_ZSTD_LEVEL);
    }

    #[test]
    fn from_negotiated_zstd() {
        let p = NegotiatedParams::from_negotiated(Some("zstd"), 512 * 1024, Some(5));
        assert!(p.is_compressed());
        assert_eq!(p.zstd_level(), 5);
        assert_eq!(p.max_chunk_size, 512 * 1024);
    }

    #[test]
    fn from_negotiated_no_compression() {
        let p = NegotiatedParams::from_negotiated(None, 128 * 1024, None);
        assert!(!p.is_compressed());
        assert_eq!(p.max_chunk_size, 128 * 1024);
    }

    #[test]
    fn from_negotiated_unknown_compression() {
        let p = NegotiatedParams::from_negotiated(Some("lz4"), 256 * 1024, None);
        assert!(!p.is_compressed());
    }

    #[test]
    fn from_negotiated_chunk_size_clamped_low() {
        let p = NegotiatedParams::from_negotiated(None, 100, None);
        assert_eq!(p.max_chunk_size, MIN_CHUNK_SIZE);
    }

    #[test]
    fn from_negotiated_chunk_size_clamped_high() {
        let p = NegotiatedParams::from_negotiated(None, 10 * 1024 * 1024, None);
        assert_eq!(p.max_chunk_size, MAX_CHUNK_SIZE);
    }

    #[test]
    fn chunk_sizer_starts_at_min() {
        let sizer = ChunkSizer::new(MAX_CHUNK_SIZE);
        assert_eq!(sizer.chunk_size(), MIN_CHUNK_SIZE);
    }

    #[test]
    fn chunk_sizer_respects_max() {
        let sizer = ChunkSizer::new(128 * 1024);
        assert!(sizer.chunk_size() <= 128 * 1024);
    }

    #[test]
    fn chunk_sizer_records_without_panic() {
        let mut sizer = ChunkSizer::new(MAX_CHUNK_SIZE);
        // Record enough bytes to trigger a re-evaluation
        for _ in 0..100 {
            sizer.record(64 * 1024);
        }
        // Should still be within bounds
        assert!(sizer.chunk_size() >= MIN_CHUNK_SIZE);
        assert!(sizer.chunk_size() <= MAX_CHUNK_SIZE);
    }
}
