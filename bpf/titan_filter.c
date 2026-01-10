// TitanDNS XDP Filter - Ultimate Production Version
// Features: DNS Acceleration (Kernel-level Cache), DDoS Protection (Blacklist), and Reflector

#define TCP_H <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- Configuration Constants ---
#define MAX_DNS_RESPONSE_LEN 768  // Extended for large CDN responses (24 × 32 bytes)
#define REFRESH_THRESHOLD_NS (10ULL * 1000000000ULL)  // Shadow Refresh when TTL < 10s

// --- Data Structures ---
// ALIGNMENT CRITICAL: Must match Rust struct exactly
struct dns_cache_entry {
    __u16 len;
    __u16 rcode;
    __u32 last_refresh_ts; // Stores ktime_get_ns() / 1e9 of last shadow refresh
    __u64 expire_ns;
    __u8 response[MAX_DNS_RESPONSE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);           // 10K blacklist rules
    __type(key, __u32);                   // Source IP (IPv4)
    __type(value, __u8);  // 1 = Drop, 2 = Refuse (XDP_TX)
} blacklist SEC(".maps");

// DNS Cache - LRU automatically evicts cold entries
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Auto-evict least recently used
    __uint(max_entries, 100000);          // 100K hot queries
    __type(key, __u64);                   // Rich hash of (qname)
    __type(value, struct dns_cache_entry);
} dns_cache SEC(".maps");

// Stats Map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);   // 0=Pass, 1=Drop, 2=CacheHit, 3=Refuse, 4=ShadowRefresh
    __type(value, __u64); // Count
} stats SEC(".maps");

// Shadow Refresh Event (sent to userspace)
struct refresh_event {
    __u64 qhash;     // Query hash to refresh
    __u64 remaining_ns;  // Remaining TTL in nanoseconds
};

// Ring Buffer for Shadow Refresh notifications
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);  // 4KB buffer (enough for ~256 events)
} refresh_ringbuf SEC(".maps");

// --- Helper Functions ---

// DJB2 Hash (64-bit) - Faster than FNV-1a, better distribution
// hash * 33 + byte (using shift: (hash << 5) + hash)
static __always_inline __u64 djb2_hash_byte(__u64 hash, __u8 byte) {
    // Lowercase ASCII
    if (byte >= 'A' && byte <= 'Z') {
        byte += 32;
    }
    return ((hash << 5) + hash) + byte; // hash * 33 + byte
}

// Parse DNS QNAME and compute Hash (RFC 1035 labels)
// Returns hash or 0 on failure/compression
static __always_inline __u64 parse_dns_qname_hash(void *dns_payload, void *data_end, void **qname_end_out) {
    __u8 *ptr = dns_payload + 12; // Skip Header
    __u64 hash = 5381ULL; // DJB2 Initial Value
    
    // Limit loop to prevent BPF verifier rejection
    #pragma unroll
    for (int i = 0; i < 64; i++) { 
        if ((void *)(ptr + 1) > data_end) return 0;
        
        __u8 byte = *ptr;
        ptr++; 
        
        if (byte == 0) {
            hash = djb2_hash_byte(hash, 0); // MUST hash the terminator
            *qname_end_out = ptr; 
            return hash;
        }
        
        // Compression pointer (0xC0) not supported in XDP fast path
        if ((byte & 0xC0) == 0xC0) return 0;
        
        hash = djb2_hash_byte(hash, byte);
    }
    return 0; // Too long
}

// Helper: Swap Ethernet Addresses
static __always_inline void swap_ethernet(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

// Helper: Swap IPv4 Addresses
static __always_inline void swap_ipv4(struct iphdr *ip) {
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
    // Checksum must be recalculated by caller after swap
    ip->check = 0; 
}

// Helper: Swap UDP Ports
static __always_inline void swap_udp(struct udphdr *udp) {
    __be16 tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp;
    udp->check = 0; // Disable UDP Checksum validation
}

// Helper: Calculate IP Checksum (for XDP_TX response)
static __always_inline __u16 calc_ip_csum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *ptr = (__u16 *)ip;

    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        csum += ptr[i];
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

SEC("xdp")
int titan_dns_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parsing Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parsing IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // --- FIREWALL LAYER ---
    __u32 src_ip = ip->saddr;
    __u8 *rule = bpf_map_lookup_elem(&blacklist, &src_ip);
    
    if (rule) {
        if (*rule == 1) {
            return XDP_DROP; // Hard Drop
        }
        if (*rule == 2) {
            // Kernel Reflector: Respond with REFUSED
            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)(ip + 1);
                if ((void *)(udp + 1) <= data_end) {
                     
                     // Verify DNS Header space
                     void *dns_header = (void *)(udp + 1);
                     if (dns_header + 12 <= data_end) {
                         // Modifying Packet in-place
                         swap_ethernet(eth);
                         swap_ipv4(ip);
                         swap_udp(udp);

                         // Fix Checksum for reflected packet
                         ip->check = calc_ip_csum(ip);

                         // Set DNS Flags: QR=1 (Response), RCODE=5 (Refused)
                         // Structure: ID(2), Flags(2)
                         // 0x8105 = Standard Query Response, Refused
                         __u16 *flags = dns_header + 2;
                         *flags = __constant_htons(0x8105);

                         return XDP_TX; // ⚡ Bounce Back!
                     }
                }
            }
            return XDP_DROP; // Fallback if parsing fails
        }
    }

    // 3. Parsing UDP Header
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 4. DNS Traffic Check (Port 53)
    if (udp->dest != __constant_htons(53))
        return XDP_PASS;

    // --- DNS PACKET PARSING ---
    void *dns_payload = (void *)(udp + 1);
    if (dns_payload + 12 > data_end)  // Need at least DNS header
        return XDP_PASS;

    // DNS Header fields
    __u16 *dns_id = dns_payload;
    __u16 orig_id = *dns_id; // Save ID before potential pointers invalidation
    __u16 *dns_flags = dns_payload + 2;
    __u16 flags_val = bpf_ntohs(*dns_flags);
    
    // Only process queries (QR=0)
    if (flags_val & 0x8000)
        return XDP_PASS;

    // --- XDP CACHE LOOKUP ---
    void *qname_end = NULL;
    __u64 qhash = parse_dns_qname_hash(dns_payload, data_end, &qname_end);
    
    // Failed to parse qname or compression pointer found
    if (qhash == 0 || qname_end == NULL)
        return XDP_PASS;

    // Rich Hashing: Incorporate QTYPE and QCLASS (4 bytes after qname)
    if (qname_end + 4 > data_end)
        return XDP_PASS;
    
    __u8 *meta_ptr = (__u8 *)qname_end;
    qhash = djb2_hash_byte(qhash, meta_ptr[0]); // QTYPE High
    qhash = djb2_hash_byte(qhash, meta_ptr[1]); // QTYPE Low
    qhash = djb2_hash_byte(qhash, meta_ptr[2]); // QCLASS High
    qhash = djb2_hash_byte(qhash, meta_ptr[3]); // QCLASS Low

    // Lookup cache using the rich u64 hash
    struct dns_cache_entry *cache_entry = bpf_map_lookup_elem(&dns_cache, &qhash);
    
    if (cache_entry) {
        __u64 now = bpf_ktime_get_ns();
        if (now > cache_entry->expire_ns) {
            // Expired -> Pass to userspace (Rust) to refresh
            // Increase Expired Stat
            // Using stats map update is too slow here, just pass.
            return XDP_PASS; 
        }

        // Cache Hit!
        // Check if TTL is low -> trigger Shadow Refresh
        __u64 remaining_ns = cache_entry->expire_ns - now;
        if (remaining_ns < REFRESH_THRESHOLD_NS && remaining_ns > 0) {
            // Rate Limit: Only trigger every 3 seconds per domain
            __u32 now_ts = (__u32)(now / 1000000000); // Current timestamp in seconds
            if (now_ts > cache_entry->last_refresh_ts + 3) {
                 // Update timestamp FIRST to avoid race (best effort)
                 cache_entry->last_refresh_ts = now_ts;
                 
                 // Low TTL but not expired -> Shadow Refresh
                 struct refresh_event *evt = bpf_ringbuf_reserve(&refresh_ringbuf, sizeof(struct refresh_event), 0);
                 if (evt) {
                     evt->qhash = qhash;
                     evt->remaining_ns = remaining_ns;
                     bpf_ringbuf_submit(evt, 0);
                 
                     // Update Shadow Refresh stat
                     __u32 sr_key = 4;  // ShadowRefresh
                     __u64 *sr_val = bpf_map_lookup_elem(&stats, &sr_key);
                     if (sr_val) __sync_fetch_and_add(sr_val, 1);
                 }
            }
        }

        // 1. Update Stats
        __u32 key = 2; // CacheHit
        __u64 *value = bpf_map_lookup_elem(&stats, &key);
        if (value) __sync_fetch_and_add(value, 1);

        // 2. Prepare Response
        // We need to modify packet in-place.
        
        __u32 new_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + cache_entry->len;
        
        // Resize packet (Adjust tail)
        int delta = new_len - (data_end - data);
        if (bpf_xdp_adjust_tail(ctx, delta))
             return XDP_PASS; // Failed to reside

        // Re-read data pointers after adjustment (Required by Verifier)
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        
        eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        
        void *payload = (void *)(udp + 1);
        
        
        // 3. Copy cached response body
        // SAFETY: We must use a constant loop bound and perform boundary checks strictly.
        __u8 *resp_ptr = cache_entry->response;
        __u32 len = cache_entry->len;
        
        if (len > MAX_DNS_RESPONSE_LEN) len = MAX_DNS_RESPONSE_LEN;

        // Copy in 32-byte chunks to reduce loop iterations/instruction count
        #pragma unroll
        for (int i = 0; i < 24; i++) { // 24 * 32 = 768 bytes
            if (len >= 32) {
                if (payload + 32 <= data_end) {
                    __builtin_memcpy(payload, resp_ptr, 32);
                    payload += 32;
                    resp_ptr += 32;
                    len -= 32;
                } else {
                    break; 
                }
            } else {
                // Handle remaining bytes (tail)
                // We use a switch/fallthrough or small byte copy
                // For simplicity/safety, just copy byte-by-byte for the tail < 32
                 #pragma unroll
                 for (int j = 0; j < 32; j++) {
                     if (len == 0) break;
                     if (payload + 1 > data_end) break;
                     *(__u8*)payload = *resp_ptr;
                     payload++;
                     resp_ptr++;
                     len--;
                 }
                 break; // Done with all
            }
        }
        
        // 4. Update Protocol Headers
        swap_ethernet(eth);
        swap_ipv4(ip);
        swap_udp(udp);
        
        // Fix IP Length
        ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + cache_entry->len);
        ip->check = 0;
        ip->check = calc_ip_csum(ip);

        // Fix UDP Length
        udp->len = bpf_htons(sizeof(struct udphdr) + cache_entry->len);
        
        // Restore Transaction ID (payload pointer was moved, recalculate)
        void *dns_start = (void *)(udp + 1);
        if (dns_start + 2 <= data_end) {
            *(__u16 *)dns_start = orig_id;
        }

        return XDP_TX;
    }

    return XDP_PASS;
}
