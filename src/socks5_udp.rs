// TitanDNS SOCKS5 UDP Proxy Support
// Enables DoQ and other UDP protocols to work through SOCKS5 proxy
// Implements SOCKS5 UDP ASSOCIATE (RFC 1928)

use anyhow::{Result, Context as AnyhowContext};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::info;

/// SOCKS5 UDP Tunnel
/// Wraps UDP traffic through SOCKS5 proxy using UDP ASSOCIATE
#[derive(Debug)]
pub struct Socks5UdpTunnel {
    /// SOCKS5 proxy address (e.g., "127.0.0.1:10000")
    proxy_addr: SocketAddr,
    /// TCP control connection (must stay alive for UDP to work)
    control_conn: Arc<Mutex<Option<TcpStream>>>,
    /// UDP relay address returned by proxy
    relay_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// Local UDP socket for sending/receiving
    local_socket: Arc<Mutex<Option<UdpSocket>>>,
}

impl Socks5UdpTunnel {
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            control_conn: Arc::new(Mutex::new(None)),
            relay_addr: Arc::new(Mutex::new(None)),
            local_socket: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize the SOCKS5 UDP ASSOCIATE
    pub async fn connect(&self) -> Result<()> {
        // 1. Establish TCP control connection
        let mut tcp = TcpStream::connect(self.proxy_addr).await
            .context("Failed to connect to SOCKS5 proxy")?;

        // 2. SOCKS5 handshake
        // Send: VER(1) NMETHODS(1) METHODS(1..255)
        tcp.write_all(&[0x05, 0x01, 0x00]).await?;  // Version 5, 1 method, NO AUTH
        
        let mut resp = [0u8; 2];
        tcp.read_exact(&mut resp).await?;
        
        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 auth failed: {:?}", resp));
        }

        // 3. UDP ASSOCIATE request
        // VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
        // CMD = 0x03 (UDP ASSOCIATE)
        // ATYP = 0x01 (IPv4)
        // DST.ADDR = 0.0.0.0 (any)
        // DST.PORT = 0 (any)
        let udp_req = [
            0x05, 0x03, 0x00, 0x01,  // VER, UDP ASSOCIATE, RSV, IPv4
            0x00, 0x00, 0x00, 0x00,  // 0.0.0.0
            0x00, 0x00,              // Port 0
        ];
        tcp.write_all(&udp_req).await?;

        // 4. Read response
        let mut header = [0u8; 4];
        tcp.read_exact(&mut header).await?;
        
        if header[1] != 0x00 {
            return Err(anyhow::anyhow!("SOCKS5 UDP ASSOCIATE failed: reply code {:02x}", header[1]));
        }

        // Parse BND.ADDR based on ATYP
        let relay_addr = match header[3] {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 4];
                let mut port = [0u8; 2];
                tcp.read_exact(&mut addr).await?;
                tcp.read_exact(&mut port).await?;
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr)),
                    u16::from_be_bytes(port)
                )
            }
            0x04 => {
                // IPv6
                let mut addr = [0u8; 16];
                let mut port = [0u8; 2];
                tcp.read_exact(&mut addr).await?;
                tcp.read_exact(&mut port).await?;
                SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr)),
                    u16::from_be_bytes(port)
                )
            }
            _ => return Err(anyhow::anyhow!("Unsupported ATYP: {:02x}", header[3])),
        };

        // 5. Handle 0.0.0.0 relay address (use proxy's IP)
        let final_relay = if relay_addr.ip().is_unspecified() {
            SocketAddr::new(self.proxy_addr.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        info!("🔗 SOCKS5 UDP relay established at {}", final_relay);

        // 6. Create local UDP socket
        let local_socket = UdpSocket::bind("0.0.0.0:0").await?;
        local_socket.connect(final_relay).await?;

        // Store connections
        *self.control_conn.lock().await = Some(tcp);
        *self.relay_addr.lock().await = Some(final_relay);
        *self.local_socket.lock().await = Some(local_socket);

        Ok(())
    }

    /// Send UDP packet through SOCKS5 proxy
    pub async fn send_to(&self, target: SocketAddr, data: &[u8]) -> Result<usize> {
        let socket = self.local_socket.lock().await;
        let socket = socket.as_ref().ok_or_else(|| anyhow::anyhow!("Tunnel not connected"))?;

        // Build SOCKS5 UDP request header
        // RSV(2) FRAG(1) ATYP(1) DST.ADDR(var) DST.PORT(2) DATA(var)
        let mut packet = Vec::with_capacity(10 + data.len());
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(1)

        match target {
            SocketAddr::V4(addr) => {
                packet.push(0x01); // ATYP IPv4
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                packet.push(0x04); // ATYP IPv6
                packet.extend_from_slice(&addr.ip().octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        packet.extend_from_slice(data);

        socket.send(&packet).await.map_err(Into::into)
    }

    /// Receive UDP packet through SOCKS5 proxy
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let socket = self.local_socket.lock().await;
        let socket = socket.as_ref().ok_or_else(|| anyhow::anyhow!("Tunnel not connected"))?;

        let mut recv_buf = vec![0u8; 65535];
        let len = socket.recv(&mut recv_buf).await?;

        if len < 10 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 UDP response"));
        }

        // Parse header
        // RSV(2) FRAG(1) ATYP(1) ...
        let atyp = recv_buf[3];
        let (addr, data_offset) = match atyp {
            0x01 => {
                // IPv4
                let ip = std::net::Ipv4Addr::new(recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7]);
                let port = u16::from_be_bytes([recv_buf[8], recv_buf[9]]);
                (SocketAddr::new(ip.into(), port), 10)
            }
            0x04 => {
                // IPv6
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&recv_buf[4..20]);
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([recv_buf[20], recv_buf[21]]);
                (SocketAddr::new(ip.into(), port), 22)
            }
            _ => return Err(anyhow::anyhow!("Unsupported ATYP in response")),
        };

        let data_len = len - data_offset;
        if data_len > buf.len() {
            return Err(anyhow::anyhow!("Buffer too small"));
        }

        buf[..data_len].copy_from_slice(&recv_buf[data_offset..len]);
        Ok((data_len, addr))
    }

    /// Check if tunnel is connected
    pub async fn is_connected(&self) -> bool {
        self.relay_addr.lock().await.is_some()
    }

    /// Close the tunnel
    pub async fn close(&self) {
        *self.control_conn.lock().await = None;
        *self.relay_addr.lock().await = None;
        *self.local_socket.lock().await = None;
    }
}

/// Wrapper for using SOCKS5 UDP with QUIC
pub struct Socks5QuicSocket {
    tunnel: Arc<Socks5UdpTunnel>,
    target: SocketAddr,
}

impl Socks5QuicSocket {
    pub async fn new(proxy_addr: SocketAddr, target: SocketAddr) -> Result<Self> {
        let tunnel = Arc::new(Socks5UdpTunnel::new(proxy_addr));
        tunnel.connect().await?;
        
        Ok(Self { tunnel, target })
    }

    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        self.tunnel.send_to(self.target, data).await
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let (len, _from) = self.tunnel.recv_from(buf).await?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_udp_tunnel_creation() {
        let tunnel = Socks5UdpTunnel::new("127.0.0.1:10000".parse().unwrap());
        assert!(!tunnel.is_connected().await);
    }
}
