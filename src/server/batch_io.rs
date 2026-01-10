// Batch I/O for Linux using recvmmsg
// This module provides high-performance packet receiving using Linux recvmmsg syscall.
// It allows receiving multiple packets with a single system call, reducing context switches.

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
#[cfg(target_os = "linux")]
// use tracing::{debug, warn}; // Removed unused imports

// Max packets per syscall (Linux Limit is typically higher)
#[cfg(target_os = "linux")]
const MAX_BATCH_SIZE: usize = 256;
#[cfg(target_os = "linux")]
const DEFAULT_BATCH_SIZE: usize = 64;
#[cfg(target_os = "linux")]
const MIN_BATCH_SIZE: usize = 32;

// Packet Buffer Size (Ethernet MTU usually 1500, but DNS can be larger)
#[cfg(target_os = "linux")]
const PACKET_SIZE: usize = 4096;

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct BatchIo {
    socket: AsyncFd<UdpSocket>,
    // Pre-allocated buffers for multiple messages
    // We use a flat vector for data to be cache friendly
    // Layout: [Packet 1 Data][Packet 2 Data]...
    buffer_pool: Vec<u8>,
    // libc::mmsghdr structures for recvmmsg
    hdrs: Vec<libc::mmsghdr>,
    // Use iovec to point to buffer_pool sections
    iovecs: Vec<libc::iovec>,
    // Sockaddrs storage
    addrs: Vec<libc::sockaddr_storage>,
    // Dynamic batch size (auto-tuned)
    batch_size: Arc<AtomicUsize>,
}

#[cfg(target_os = "linux")]
impl BatchIo {
    /// Create a new BatchIo handler for a UdpSocket
    pub fn new(socket: UdpSocket) -> Result<Self> {
        socket.set_nonblocking(true)?;
        
        let buffer_pool = vec![0u8; MAX_BATCH_SIZE * PACKET_SIZE];
        let mut hdrs = Vec::with_capacity(MAX_BATCH_SIZE);
        let mut iovecs = Vec::with_capacity(MAX_BATCH_SIZE);
        let mut addrs = Vec::with_capacity(MAX_BATCH_SIZE);

        // Compute offsets and layout
        for i in 0..MAX_BATCH_SIZE {
            // Setup buffer pointers
            let offset = i * PACKET_SIZE;
            let ptr = unsafe { buffer_pool.as_ptr().add(offset) } as *mut libc::c_void;
            
            // Push placeholders
            iovecs.push(libc::iovec {
                iov_base: ptr,
                iov_len: PACKET_SIZE,
            });
            addrs.push(unsafe { std::mem::zeroed() });
            
            // Push zeroed header
            let msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdrs.push(libc::mmsghdr {
                msg_hdr,
                msg_len: 0,
            });
        }

        Ok(Self {
            socket: AsyncFd::new(socket)?,
            buffer_pool,
            hdrs,
            iovecs,
            addrs,
            batch_size: Arc::new(AtomicUsize::new(DEFAULT_BATCH_SIZE)),
        })
    }

    /// Receive a batch of packets
    /// Returns: Count of packets received
    pub async fn recv_batch(&mut self) -> Result<usize> {
        let fd = self.socket.get_ref().as_raw_fd();

        loop {
            let batch_size = self.current_batch_size();
            let mut guard = self.socket.readable_mut().await?;
            
            // Re-initialize headers for each call
            for i in 0..batch_size {
                 self.hdrs[i].msg_hdr.msg_name = &mut self.addrs[i] as *mut _ as *mut libc::c_void;
                 self.hdrs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                 self.hdrs[i].msg_hdr.msg_iov = &mut self.iovecs[i];
                 self.hdrs[i].msg_hdr.msg_iovlen = 1;
                 self.hdrs[i].msg_len = 0;
            }

            let io_res = guard.try_io(|_inner| {
                let res = unsafe {
                    libc::recvmmsg(
                        fd,
                        self.hdrs.as_mut_ptr(),
                        batch_size as u32,
                        0, // flags
                        std::ptr::null_mut(), // timeout
                    )
                };
                
                if res < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                         return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                    }
                    return Err(err);
                }
                
                Ok(res as usize)
            });

            match io_res {
                Ok(result) => return result.map_err(Into::into),
                Err(_would_block) => {
                    // Yield to prevent busy loop on spurious wakeups
                    tokio::task::yield_now().await;
                    continue;
                }
            }
        }
    }

    /// Auto-tune batch size by QPS
    pub fn auto_tune_batch_size(&self, current_qps: u64) {
        let new_size = if current_qps > 100_000 {
            256
        } else if current_qps < 10_000 {
            32
        } else {
            64
        };

        let size = new_size.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE);
        let old = self.batch_size.load(Ordering::Relaxed);
        if old != size {
            self.batch_size.store(size, Ordering::Relaxed);
        }
    }

    #[inline]
    fn current_batch_size(&self) -> usize {
        let size = self.batch_size.load(Ordering::Relaxed);
        size.clamp(MIN_BATCH_SIZE, MAX_BATCH_SIZE)
    }

    /// Try to clone the underlying socket (for sending responses)
    pub fn try_clone_socket(&self) -> Result<std::net::UdpSocket> {
        self.socket.get_ref().try_clone().map_err(Into::into)
    }

    /// Access a received packet data
    /// Unsafe because it refers to internal buffer which changes on next recv
    pub fn get_packet(&self, index: usize) -> Option<(&[u8], std::net::SocketAddr)> {
        if index >= self.hdrs.len() {
            return None;
        }
        
        let len = self.hdrs[index].msg_len as usize;
        if len == 0 {
            return None; 
        }

        let start = index * PACKET_SIZE;
        let end = start + len;
        let data = &self.buffer_pool[start..end];
        
        // Convert sockaddr
        let addr = unsafe {
            let storage = &self.addrs[index];
            let len = self.hdrs[index].msg_hdr.msg_namelen;
            // Use socket2::SockAddr::new which takes storage and len
            socket2::SockAddr::new(
                 *storage, 
                 len
            ).as_socket()
        };

        match addr {
            Some(a) => Some((data, a)),
            None => None,
        }
    }
}

// Fallback for non-Linux
#[cfg(not(target_os = "linux"))]
pub struct BatchIo;

// Mark BatchIo as Send because we only access its internal pointers from the thread that owns it.
// The raw pointers point to the stable `buffer_pool` and `addrs` vectors owned by the struct itself.
unsafe impl Send for BatchIo {}


