//! Bounded byte capture shared by compute backends; never buffers an entire line.
use crate::runtime::TaskOutput;
use std::collections::VecDeque;
const CAPACITY: usize = 1024 * 1024;
#[derive(Default)]
pub(crate) struct OutputCapture {
    bytes: VecDeque<u8>,
    end: u64,
}
impl OutputCapture {
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.end = self.end.saturating_add(bytes.len() as u64);
        let keep = bytes.len().min(CAPACITY);
        let evict = (self.bytes.len() + keep).saturating_sub(CAPACITY);
        self.bytes.drain(..evict);
        self.bytes.extend(&bytes[bytes.len() - keep..]);
    }
    pub fn read(&self, cursor: u64) -> TaskOutput {
        let base = self.end - self.bytes.len() as u64;
        let start = cursor.max(base).min(self.end);
        let bytes: Vec<u8> = self
            .bytes
            .iter()
            .skip((start - base) as usize)
            .copied()
            .collect();
        // A trailing partial UTF-8 scalar stays pending until the next read.
        let mut complete = 0;
        while complete < bytes.len() {
            match std::str::from_utf8(&bytes[complete..]) {
                Ok(_) => {
                    complete = bytes.len();
                    break;
                }
                Err(e) => {
                    complete += e.valid_up_to();
                    match e.error_len() {
                        Some(invalid) => complete += invalid,
                        None => break,
                    }
                }
            }
        }
        TaskOutput {
            text: String::from_utf8_lossy(&bytes[..complete]).into_owned(),
            next_cursor: start + complete as u64,
            dropped_bytes: base.saturating_sub(cursor),
        }
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes.iter().copied().collect::<Vec<_>>()).into_owned()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_capture_tracks_loss_and_partial_unicode() {
        let mut capture = OutputCapture::default();
        capture.extend_from_slice(&vec![b'x'; CAPACITY * 3]);
        assert_eq!(capture.bytes.len(), CAPACITY);
        assert_eq!(capture.read(0).dropped_bytes, (CAPACITY * 2) as u64);
        let cursor = capture.read(0).next_cursor;
        capture.extend_from_slice(&[0xe2, 0x82]);
        assert_eq!(capture.read(cursor).next_cursor, cursor);
        capture.extend_from_slice(&[0xac]);
        assert_eq!(capture.read(cursor).text, "€");
        assert!(capture.read(cursor + 3).text.is_empty());
        let mut invalid = OutputCapture::default();
        invalid.extend_from_slice(&[0xff, 0xe2, 0x82]);
        let first = invalid.read(0);
        assert_eq!(first.text, "�");
        assert_eq!(first.next_cursor, 1);
        invalid.extend_from_slice(&[0xac]);
        assert_eq!(invalid.read(first.next_cursor).text, "€");
    }
}
