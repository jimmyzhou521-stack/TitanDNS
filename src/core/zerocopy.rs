// Zero-Copy DNS Message - Owned Version
// Uses bytes::Bytes for zero-copy, reference-counted buffer management
// Compatible with hickory_proto::Message for gradual migration
//
// Performance: 
// - Eliminates per-packet allocations
// - Lazy parsing: only parse what's needed
// - Cheap cloning (reference count increment)

#![allow(dead_code)]

use bytes::{Bytes, BytesMut};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use once_cell::sync::OnceCell;
use std::sync::Arc;

/// DNS Header (fixed 12 bytes) - for direct memory access
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct DnsHeaderRaw {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// Zero-Copy DNS Message with owned Bytes buffer
/// 
/// This is the core type for TitanDNS's zero-allocation DNS processing.
/// It holds an immutable, reference-counted byte buffer and lazily parses
/// DNS sections on demand.
#[derive(Clone)]
pub struct ZeroCopyDnsMessage {
    /// Raw DNS packet data (reference-counted, zero-copy clone)
    raw: Bytes,
    
    /// Lazily parsed hickory Message (for compatibility with existing plugins)
    /// Using Arc<OnceCell> for thread-safe lazy initialization
    parsed: Arc<OnceCell<Message>>,
    
    /// Cached header fields (parsed immediately, very fast)
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
}

impl ZeroCopyDnsMessage {
    /// Create from raw bytes (zero-copy if input is Bytes)
    pub fn from_bytes(data: Bytes) -> Result<Self, &'static str> {
        if data.len() < 12 {
            return Err("DNS message too short");
        }

        // Parse header fields directly (no allocation)
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        Ok(Self {
            raw: data,
            parsed: Arc::new(OnceCell::new()),
            id,
            flags,
            qdcount,
            ancount,
        })
    }

    /// Create from Vec<u8> (takes ownership, no copy)
    pub fn from_vec(data: Vec<u8>) -> Result<Self, &'static str> {
        Self::from_bytes(Bytes::from(data))
    }

    /// Create from hickory Message (serializes to Bytes)
    pub fn from_message(msg: &Message) -> Result<Self, anyhow::Error> {
        let bytes = msg.to_vec()?;
        Self::from_bytes(Bytes::from(bytes)).map_err(|e| anyhow::anyhow!(e))
    }

    // ==================== Fast Header Access (Zero Parsing) ====================

    /// Get message ID
    #[inline]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Check if this is a query
    #[inline]
    pub fn is_query(&self) -> bool {
        (self.flags & 0x8000) == 0
    }

    /// Check if this is a response
    #[inline]
    pub fn is_response(&self) -> bool {
        !self.is_query()
    }

    /// Get response code (RCODE)
    #[inline]
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    /// Get question count
    #[inline]
    pub fn question_count(&self) -> u16 {
        self.qdcount
    }

    /// Get answer count
    #[inline]
    pub fn answer_count(&self) -> u16 {
        self.ancount
    }

    // ==================== Raw Data Access (Zero-Copy) ====================

    /// Get raw bytes (zero-copy reference)
    #[inline]
    pub fn raw_bytes(&self) -> &Bytes {
        &self.raw
    }

    /// Get raw slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.raw
    }

    /// Get raw bytes length
    #[inline]
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    // ==================== Hickory Compatibility (Lazy Parsing) ====================

    /// Get parsed hickory Message (lazy, cached)
    /// This is the bridge to existing plugin code
    pub fn as_message(&self) -> Result<&Message, anyhow::Error> {
        self.parsed.get_or_try_init(|| {
            Message::from_vec(&self.raw).map_err(|e| anyhow::anyhow!("Parse error: {}", e))
        })
    }

    /// Convert to owned hickory Message (clones parsed structure)
    pub fn to_message(&self) -> Result<Message, anyhow::Error> {
        self.as_message().cloned()
    }

    /// Get query name (lazy parsed, cached in Message)
    pub fn query_name(&self) -> Result<String, anyhow::Error> {
        let msg = self.as_message()?;
        Ok(msg.query()
            .map(|q| q.name().to_string())
            .unwrap_or_else(|| ".".to_string()))
    }

    /// Get query type
    pub fn query_type(&self) -> Result<RecordType, anyhow::Error> {
        let msg = self.as_message()?;
        Ok(msg.query()
            .map(|q| q.query_type())
            .unwrap_or(RecordType::A))
    }

    // ==================== Response Building ====================

    /// Create a modified copy with new ID
    pub fn with_id(&self, new_id: u16) -> Self {
        let mut new_raw = BytesMut::from(self.raw.as_ref());
        new_raw[0] = (new_id >> 8) as u8;
        new_raw[1] = (new_id & 0xFF) as u8;
        
        Self {
            raw: new_raw.freeze(),
            parsed: Arc::new(OnceCell::new()), // Reset parsed cache
            id: new_id,
            flags: self.flags,
            qdcount: self.qdcount,
            ancount: self.ancount,
        }
    }

    /// Serialize to Vec<u8> (for sending)
    pub fn to_vec(&self) -> Vec<u8> {
        self.raw.to_vec()
    }
}

impl std::fmt::Debug for ZeroCopyDnsMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroCopyDnsMessage")
            .field("id", &self.id)
            .field("is_response", &self.is_response())
            .field("rcode", &self.rcode())
            .field("questions", &self.qdcount)
            .field("answers", &self.ancount)
            .field("len", &self.raw.len())
            .finish()
    }
}

// ==================== Question Parser (Zero-Copy) ====================

/// Zero-copy DNS question accessor
pub struct ZeroCopyQuestion<'a> {
    data: &'a [u8],
    name_end: usize,
    qtype: u16,
    qclass: u16,
}

impl ZeroCopyDnsMessage {
    /// Parse first question (zero-copy, no allocation)
    pub fn parse_question(&self) -> Option<ZeroCopyQuestion<'_>> {
        if self.qdcount == 0 || self.raw.len() < 17 {
            return None;
        }

        let data = &self.raw[12..]; // Skip header
        let name_end = Self::find_name_end(data)?;
        
        if data.len() < name_end + 4 {
            return None;
        }

        let qtype = u16::from_be_bytes([data[name_end], data[name_end + 1]]);
        let qclass = u16::from_be_bytes([data[name_end + 2], data[name_end + 3]]);

        Some(ZeroCopyQuestion {
            data,
            name_end,
            qtype,
            qclass,
        })
    }

    fn find_name_end(data: &[u8]) -> Option<usize> {
        let mut pos = 0;
        loop {
            if pos >= data.len() {
                return None;
            }

            let len = data[pos] as usize;
            
            // Compression pointer
            if len & 0xC0 == 0xC0 {
                return Some(pos + 2);
            }
            
            // End of name
            if len == 0 {
                return Some(pos + 1);
            }

            pos += len + 1;
            
            // Safety limit
            if pos > 255 {
                return None;
            }
        }
    }
}

impl<'a> ZeroCopyQuestion<'a> {
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    /// Get raw name bytes (wire format, not human readable)
    pub fn name_bytes(&self) -> &'a [u8] {
        &self.data[..self.name_end]
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let data = Bytes::from(vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Flags (response, no error)
            0x00, 0x01, // QDCOUNT
            0x00, 0x02, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // ... question and answers would follow
        ]);

        let msg = ZeroCopyDnsMessage::from_bytes(data).unwrap();
        assert_eq!(msg.id(), 0x1234);
        assert!(msg.is_response());
        assert_eq!(msg.rcode(), 0);
        assert_eq!(msg.question_count(), 1);
        assert_eq!(msg.answer_count(), 2);
    }

    #[test]
    fn test_clone_is_cheap() {
        let data = Bytes::from(vec![0u8; 512]);
        let msg = ZeroCopyDnsMessage::from_bytes(data).unwrap();
        
        let cloned = msg.clone();
        
        // Both point to same underlying data
        assert_eq!(msg.raw_bytes().as_ptr(), cloned.raw_bytes().as_ptr());
    }

    #[test]
    fn test_with_id() {
        let data = Bytes::from(vec![
            0x12, 0x34, // ID = 0x1234
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let msg = ZeroCopyDnsMessage::from_bytes(data).unwrap();
        assert_eq!(msg.id(), 0x1234);

        let modified = msg.with_id(0xABCD);
        assert_eq!(modified.id(), 0xABCD);
        
        // Original unchanged
        assert_eq!(msg.id(), 0x1234);
    }
}
