#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

// #define VERBOSE

#define UNUSED(x) ((void)(x))

#define PAGE_SIZE 0x1000
#define BUFFER_SIZE 0x10000

#define PREFIX_BYTES 12
#define HOST_BYTES   4

#define LOCAL_PREFIX  "2001:db8:1:4646::"  // /96
#define REMOTE_PREFIX "2001:db8:2:4646::"  // /96

#define IPV4_DF_BIT 0x4000
#define IPV4_NEXT_HEADER_ICMP 1
#define IPV6_NEXT_HEADER_ICMP 58

typedef struct
{
    uint8_t version_header_len;
    uint8_t dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags;
    uint8_t hop_limit;
    uint8_t next_header;
    uint16_t checksum;
    union
    {
        uint32_t src;
        uint8_t src_bytes[4];
    };
    union
    {
        uint32_t dst;
        uint8_t dst_bytes[4];
    };
} __attribute__((packed)) ipv4_header_t;

typedef struct
{
    uint32_t version_flow;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    union
    {
        struct
        {
            uint64_t src_hi;
            uint64_t src_lo;
        };
        uint8_t src_bytes[16];
    };
    union
    {
        struct
        {
            uint64_t dst_hi;
            uint64_t dst_lo;
        };
        uint8_t dst_bytes[16];
    };
} __attribute__((packed)) ipv6_header_t;

#define ICMPV4_TYPE_TTL 11
#define ICMPV4_CODE_TTL 0
#define ICMPV6_TYPE_TTL 3
#define ICMPV6_CODE_TTL 0

#define ICMPV4_TYPE_TOO_BIG 3
#define ICMPV4_CODE_TOO_BIG 4
#define ICMPV6_TYPE_TOO_BIG 2
#define ICMPV6_CODE_TOO_BIG 0

typedef struct
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union
    {
        uint8_t rest_bytes[4];
        uint32_t rest;
        struct
        {
            uint16_t ununsed1;
            uint16_t mtu;
        };
    };
} __attribute__((packed)) icmpv4_header_t;

typedef struct
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union
    {
        uint8_t rest_bytes[4];
        uint32_t rest;
        struct
        {
            uint16_t ununsed1;
            uint16_t mtu;
        };
    };
} __attribute__((packed)) icmpv6_header_t;

uint8_t local_prefix[16];
uint8_t remote_prefix[16];

int tun_alloc(const char *name, int flags)
{
    const char *clonedev = "/dev/net/tun";

    int fd;
    if ((fd = open(clonedev, O_RDWR)) < 0)
    {
        return fd;
    }

    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    if (name)
    {
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
    }
    ifr.ifr_flags = flags;

    int err;
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        close(fd);
        return err;
    }

    printf("Open tun/tap device: %s for reading...\n", ifr.ifr_name);
    return fd;
}

void print_hex(void *buff, size_t len)
{
    char *ch = (char *)buff;
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02hhx ", ch[i]);
    }
}

int get_version(void *pkt)
{
    ipv4_header_t *v4pkt = (ipv4_header_t *)pkt;
    return v4pkt->version_header_len >> 4;
}

void print_ipv4_packet(ipv4_header_t *v4pkt)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, v4pkt->src_bytes, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, v4pkt->dst_bytes, dst, INET_ADDRSTRLEN);
    printf("[IPv4] %s -> %s: header_len=%d, total_len=%d\n",
           src, dst,
           4 * (v4pkt->version_header_len & 0xf), ntohs(v4pkt->total_len));
}

void print_ipv6_packet(ipv6_header_t *v6pkt)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, v6pkt->src_bytes, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, v6pkt->dst_bytes, dst, INET6_ADDRSTRLEN);
    printf("[IPv6] %s -> %s: payload_len=%d\n", src, dst, ntohs(v6pkt->payload_len));
}

ssize_t v4_to_v6(ipv6_header_t *v6pkt, size_t v6len, const ipv4_header_t *v4pkt, size_t v4len,
                 size_t copy_len)
{
    if (v4len < sizeof(ipv4_header_t)) return -1;
    if (v6len < sizeof(ipv6_header_t)) return -2;
    size_t v4header_len = 4 * (v4pkt->version_header_len & 0xf);
    uint16_t payload_len = ntohs(v4pkt->total_len) - v4header_len;
    if (payload_len < copy_len) copy_len = payload_len;
    if (v4len < v4header_len + copy_len) return -3;
    if (v6len < sizeof(ipv6_header_t) + copy_len) return -4;

    // Translate the header.
    v6pkt->version_flow = htonl(0x60000000);
    v6pkt->payload_len = htons(payload_len);
    v6pkt->next_header = v4pkt->next_header;
    v6pkt->hop_limit = v4pkt->hop_limit;

    // Translate addresses.
    memcpy(v6pkt->src_bytes, local_prefix, PREFIX_BYTES);
    memcpy(v6pkt->src_bytes + PREFIX_BYTES, v4pkt->src_bytes, HOST_BYTES);
    memcpy(v6pkt->dst_bytes, remote_prefix, PREFIX_BYTES);
    memcpy(v6pkt->dst_bytes + PREFIX_BYTES, v4pkt->dst_bytes, HOST_BYTES);

    // Copy payload.
    memcpy(v6pkt + 1, (uint8_t *)v4pkt + v4header_len, copy_len);
    return sizeof(ipv6_header_t) + copy_len;
}

static inline uint32_t ip_checksum_partial(const void *buff, size_t len)
{
    uint32_t checksum = 0;
    const uint16_t *buff16 = (const uint16_t *)buff;
    for (int i = 0; i < len / sizeof(uint16_t); ++i)
    {
        checksum += ntohs(buff16[i]);
    }
    if (len & 1) checksum += ((const uint8_t *)buff)[len - 1];
    return checksum;
}

static inline uint16_t ip_checksum_final(uint32_t checksum)
{
    checksum = (checksum & 0xffff) + (checksum >> 16);
    return ~htons(checksum & 0xffff);
}

ssize_t icmpv6_to_icmpv4(icmpv4_header_t *v4pkt, size_t v4len,
                         const icmpv6_header_t *v6pkt, size_t v6len);

ssize_t v6_to_v4(ipv4_header_t *v4pkt, size_t v4len, const ipv6_header_t *v6pkt, size_t v6len,
                 size_t copy_len)
{
    if (v6len < sizeof(ipv6_header_t)) return -5;
    if (v4len < sizeof(ipv4_header_t)) return -6;
    uint16_t payload_len = ntohs(v6pkt->payload_len);
    if (payload_len < copy_len) copy_len = payload_len;
    if (v6len < sizeof(ipv6_header_t) + copy_len) return -7;
    if (v4len < sizeof(ipv4_header_t) + copy_len) return -8;
    const uint8_t *dst_prefix = local_prefix, *src_prefix = remote_prefix;
    if (memcmp(v6pkt->dst_bytes, remote_prefix, PREFIX_BYTES) == 0)
    {
        // Local prefix and remote prefix have been swapped, which means this is a packet in
        // an ICMP error packet.
        dst_prefix = remote_prefix;
        src_prefix = local_prefix;
    }
    else
    {
        if (memcmp(v6pkt->dst_bytes, dst_prefix, PREFIX_BYTES) != 0) return -9;  // Not implemented.
    }

    // Translate the header.
    v4pkt->version_header_len = 0x45;
    v4pkt->dscp_ecn = 0;
    v4pkt->total_len = htons(sizeof(ipv4_header_t) + payload_len);
    v4pkt->id = 0;
    v4pkt->flags = htons(IPV4_DF_BIT);
    v4pkt->hop_limit = v6pkt->hop_limit;
    v4pkt->next_header = v6pkt->next_header;
    v4pkt->checksum = 0;

    // Translate addresses.
    if (memcmp(v6pkt->src_bytes, src_prefix, PREFIX_BYTES) == 0)
    {
        memcpy(v4pkt->src_bytes, v6pkt->src_bytes + PREFIX_BYTES, HOST_BYTES);
    }
    else
    {
        // memcpy(v4pkt->src_bytes, v6pkt->src_bytes + PREFIX_BYTES, HOST_BYTES);
        // FIXME: new translation design needed
        // Use CGN addresses.
        v4pkt->src_bytes[0] = 100;
        v4pkt->src_bytes[1] = 0x40 | (v6pkt->src_bytes[7] & 0x3f);
        v4pkt->src_bytes[2] = v6pkt->src_bytes[14];
        v4pkt->src_bytes[3] = v6pkt->src_bytes[15];
    }
    memcpy(v4pkt->dst_bytes, v6pkt->dst_bytes + PREFIX_BYTES, HOST_BYTES);

    if (copy_len == payload_len && v6pkt->next_header == IPV6_NEXT_HEADER_ICMP)
    {
        // We are going to copy all of the payload, but this is an ICMP packet,
        // so we should translate it.
#ifdef VERBOSE
        printf("  This is an ICMP packet.\n");
#endif
        int ret = icmpv6_to_icmpv4((icmpv4_header_t *)(v4pkt + 1), v4len - sizeof(ipv4_header_t),
                                   (icmpv6_header_t *)(v6pkt + 1), v6len - sizeof(ipv6_header_t));
        if (ret <= 0) return ret;
        copy_len = payload_len = ret;
        v4pkt->total_len = htons(sizeof(ipv4_header_t) + payload_len);
        v4pkt->next_header = IPV4_NEXT_HEADER_ICMP;
    }
    else
    {
        // Copy payload.
        memcpy(v4pkt + 1, v6pkt + 1, copy_len);
    }

    // Calculate IPv4 checksum.
    v4pkt->checksum = ip_checksum_final(ip_checksum_partial(v4pkt, sizeof(ipv4_header_t)));
    return sizeof(ipv4_header_t) + copy_len;
}

static inline ssize_t icmpv6_to_icmpv4_payload(icmpv4_header_t *v4pkt, size_t v4len,
                                               const icmpv6_header_t *v6pkt, size_t v6len)
{
    int ret;
    if ((ret = v6_to_v4((ipv4_header_t *)(v4pkt + 1), v4len - sizeof(icmpv4_header_t),
                        (ipv6_header_t *)(v6pkt + 1), v6len - sizeof(icmpv6_header_t), 8)) <= 0)
    {
        return ret;
    }

    size_t len = sizeof(icmpv4_header_t) + sizeof(ipv4_header_t) + 8;
    v4pkt->checksum = ip_checksum_final(ip_checksum_partial(v4pkt, len));
    return len;
}

ssize_t icmpv6_to_icmpv4(icmpv4_header_t *v4pkt, size_t v4len,
                         const icmpv6_header_t *v6pkt, size_t v6len)
{
    if (v6len < sizeof(icmpv6_header_t)) return -10;
    if (v4len < sizeof(icmpv4_header_t)) return -11;
    if (v6pkt->type == ICMPV6_TYPE_TTL && v6pkt->code == ICMPV6_CODE_TTL)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (hop limit exceeded).\n");
#endif
        bzero(v4pkt, sizeof(icmpv4_header_t));
        v4pkt->type = ICMPV4_TYPE_TTL;
        v4pkt->code = ICMPV4_CODE_TTL;
        v4pkt->checksum = 0;
        v4pkt->rest = 0;
        return icmpv6_to_icmpv4_payload(v4pkt, v4len, v6pkt, v6len);
    }
    if (v6pkt->type == ICMPV6_TYPE_TOO_BIG && v6pkt->code == ICMPV6_CODE_TOO_BIG)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (too big).\n");
#endif
        v4pkt->type = ICMPV4_TYPE_TOO_BIG;
        v4pkt->code = ICMPV4_CODE_TOO_BIG;
        v4pkt->checksum = 0;
        v4pkt->ununsed1 = 0;
        // Adjust overhead.
        v4pkt->mtu = htons(ntohs(v6pkt->mtu) - sizeof(ipv6_header_t) + sizeof(ipv4_header_t));
        return icmpv6_to_icmpv4_payload(v4pkt, v4len, v6pkt, v6len);
    }
    printf("Unknown ICMP type %d code %d.\n", v6pkt->type, v6pkt->code);
    return -12;
}

void *guarded_malloc(size_t len)
{
    len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint8_t *ret = mmap(NULL, PAGE_SIZE + len + PAGE_SIZE, PROT_READ,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }
    mprotect(ret + PAGE_SIZE, len, PROT_READ | PROT_WRITE);
    return ret + PAGE_SIZE;
}

int main(int argc, const char **argv)
{
    const char *name = "tun464";
    if (argc < 2)
    {
        printf("Usage: %s dev_name [local_prefix remote_prefix]\n", argv[0]);
        return 1;
    }
    name = argv[1];
    if (argc >= 4)
    {
        inet_pton(AF_INET6, argv[2], local_prefix);
        inet_pton(AF_INET6, argv[3], remote_prefix);
    }
    else
    {
        inet_pton(AF_INET6, LOCAL_PREFIX, local_prefix);
        inet_pton(AF_INET6, REMOTE_PREFIX, remote_prefix);
    }

    int tun_fd = tun_alloc(name, IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0)
    {
        perror("Allocating interface");
        exit(1);
    }

    setuid(65534);
    setgid(65534);
    seteuid(65534);
    setegid(65534);

    char *buffer = guarded_malloc(BUFFER_SIZE), *new_buffer = guarded_malloc(BUFFER_SIZE);
    while (1)
    {
        ssize_t len = read(tun_fd, buffer, BUFFER_SIZE);
        if (len <= 0)
        {
            perror("Reading from interface");
            close(tun_fd);
            exit(1);
        }

        int version = get_version(buffer);
        if (version == 4)
        {
#ifdef VERBOSE
            print_ipv4_packet((ipv4_header_t *)buffer);
#endif
            ssize_t new_len = v4_to_v6((ipv6_header_t *)new_buffer, BUFFER_SIZE,
                                       (ipv4_header_t *)buffer, len, -1);
            if (new_len > 0)
            {
#ifdef VERBOSE
                printf("  translated: ");
                print_ipv6_packet((ipv6_header_t *)new_buffer);
#endif
                ssize_t ret = write(tun_fd, new_buffer, new_len);
                if (ret <= 0)
                {
                    perror("write");
                }
            }
            else
            {
#ifndef VERBOSE
                print_ipv4_packet((ipv4_header_t *)buffer);
#endif
                printf("  translation failed: %ld\n", new_len);
            }
        }
        if (version == 6)
        {
#ifdef VERBOSE
            print_ipv6_packet((ipv6_header_t *)buffer);
#endif
            ssize_t new_len = v6_to_v4((ipv4_header_t *)new_buffer, BUFFER_SIZE,
                                       (ipv6_header_t *)buffer, len, -1);
            if (new_len > 0)
            {
#ifdef VERBOSE
                printf("  translated: ");
                print_ipv4_packet((ipv4_header_t *)new_buffer);
#endif
                ssize_t ret = write(tun_fd, new_buffer, new_len);
                if (ret <= 0)
                {
                    perror("write");
                }
            }
            else
            {
#ifndef VERBOSE
                print_ipv6_packet((ipv6_header_t *)buffer);
#endif
                printf("  translation failed: %ld\n", new_len);
                print_hex(buffer, len);
                printf("\n");
            }
        }
    }
    return 0;
}
