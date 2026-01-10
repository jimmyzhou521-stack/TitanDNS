#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use anyhow::Result;
#[cfg(target_os = "linux")]
use socket2::SockAddr;
#[cfg(target_os = "linux")]
use bytes::Bytes;

#[cfg(target_os = "linux")]
pub struct BatchSender {
    socket: Arc<UdpSocket>,
    // Store pending packets: (data, target_addr)
    queue: Vec<(Bytes, SocketAddr)>,
    max_batch: usize,
}

#[cfg(target_os = "linux")]
impl BatchSender {
    pub fn new(socket: Arc<UdpSocket>, max_batch: usize) -> Self {
        Self {
            socket,
            queue: Vec::with_capacity(max_batch),
            max_batch,
        }
    }

    /// Add a packet to the specific queue. Returns true if batch is full and should be flushed.
    pub fn push(&mut self, data: Bytes, addr: SocketAddr) -> bool {
        self.queue.push((data, addr));
        self.queue.len() >= self.max_batch
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Flush all pending packets using sendmmsg
    pub fn flush(&mut self) -> Result<usize> {
        if self.queue.is_empty() {
            return Ok(0);
        }

        let fd = self.socket.as_raw_fd();
        let batch_size = self.queue.len();

        // Prepare mmsghdr structures
        // We need to keep iovecs and sockaddrs alive during the syscall
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(batch_size);
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(batch_size);
        let mut sockaddrs: Vec<SockAddr> = Vec::with_capacity(batch_size);

        for (data, addr) in &self.queue {
            // Convert address to socket2::SockAddr (which wraps libc::sockaddr_storage)
            let saddr = SockAddr::from(*addr);
            sockaddrs.push(saddr);
            
            // Setup iovec
            iovecs.push(libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            });
        }

        // Link everything into hdrs
        for i in 0..batch_size {
            let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            
            // Send To Address
            msg_hdr.msg_name = sockaddrs[i].as_ptr() as *mut libc::c_void;
            msg_hdr.msg_namelen = sockaddrs[i].len();

            // Data
            msg_hdr.msg_iov = &mut iovecs[i];
            msg_hdr.msg_iovlen = 1;

            hdrs.push(libc::mmsghdr {
                msg_hdr,
                msg_len: 0,
            });
        }

        // Syscall: sendmmsg
        let res = unsafe {
            libc::sendmmsg(
                fd,
                hdrs.as_mut_ptr(),
                batch_size as u32,
                0, // flags
            )
        };

        // Clear queue regardless of success (to prevent stuck packets, or retry logic could be added)
        self.queue.clear();

        if res < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(res as usize)
    }
}
