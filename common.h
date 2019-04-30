#ifndef _TUN464_COMMON_H_
#define _TUN464_COMMON_H_

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

// #define VERBOSE
#define LOG_ERROR
#define TRANSLATE_UDP
#define TRANSLATE_TCP

#define UNUSED(x) ((void)(x))

#define PAGE_SIZE 0x1000
#define BUFFER_SIZE 0x10000

#define PREFIX_BYTES 12
#define HOST_BYTES   4

#define LOCAL_PREFIX  "2001:db8:1:4646::"  // /96
#define REMOTE_PREFIX "2001:db8:2:4646::"  // /96

#define IPV4_DF_BIT 0x4000
#define IPV4_MF_BIT 0x2000
#define IPV4_NEXT_HEADER_ICMP 1
#define IPV6_MF_BIT 0x0001
#define IPV6_NEXT_HEADER_ICMP 58
#define IPV6_NEXT_HEADER_FRAGMENT 44
#define IP_NEXT_HEADER_UDP 17
#define IP_NEXT_HEADER_TCP 6

#define ICMPV4_TYPE_TTL 0x0b
#define ICMPV4_CODE_TTL 0x00
#define ICMPV6_TYPE_TTL 0x03
#define ICMPV6_CODE_TTL 0x00

#define ICMPV4_TYPE_DEFRAG 0x0b
#define ICMPV4_CODE_DEFRAG 0x01
#define ICMPV6_TYPE_DEFRAG 0x03
#define ICMPV6_CODE_DEFRAG 0x01

#define ICMPV4_TYPE_TOO_BIG 0x03
#define ICMPV4_CODE_TOO_BIG 0x04
#define ICMPV6_TYPE_TOO_BIG 0x02
#define ICMPV6_CODE_TOO_BIG 0x00

#define ICMPV4_TYPE_ECHO_REQUEST 0x08
#define ICMPV4_CODE_ECHO_REQUEST 0x00
#define ICMPV6_TYPE_ECHO_REQUEST 0x80
#define ICMPV6_CODE_ECHO_REQUEST 0x00

#define ICMPV4_TYPE_ECHO_REPLY 0x00
#define ICMPV4_CODE_ECHO_REPLY 0x00
#define ICMPV6_TYPE_ECHO_REPLY 0x81
#define ICMPV6_CODE_ECHO_REPLY 0x00

#define ICMPV4_TYPE_NETWORK_UNREACHABLE 0x03
#define ICMPV4_CODE_NETWORK_UNREACHABLE 0x00
#define ICMPV6_TYPE_NETWORK_UNREACHABLE 0x01
#define ICMPV6_CODE_NETWORK_UNREACHABLE 0x00

#define ICMPV4_TYPE_ADDRESS_UNREACHABLE 0x03
#define ICMPV4_CODE_ADDRESS_UNREACHABLE 0x01
#define ICMPV6_TYPE_ADDRESS_UNREACHABLE 0x01
#define ICMPV6_CODE_ADDRESS_UNREACHABLE 0x03

#define ICMPV4_TYPE_PORT_UNREACHABLE 0x03
#define ICMPV4_CODE_PORT_UNREACHABLE 0x03
#define ICMPV6_TYPE_PORT_UNREACHABLE 0x01
#define ICMPV6_CODE_PORT_UNREACHABLE 0x04

// For little-endian systems.
#define ICMPV4_TYPE_CODE_TTL 0x000b
#define ICMPV6_TYPE_CODE_TTL 0x0003

#define ICMPV4_TYPE_CODE_DEFRAG 0x010b
#define ICMPV6_TYPE_CODE_DEFRAG 0x0103

#define ICMPV4_TYPE_CODE_TOO_BIG 0x0403
#define ICMPV6_TYPE_CODE_TOO_BIG 0x0002

#define ICMPV4_TYPE_CODE_ECHO_REQUEST 0x0008
#define ICMPV6_TYPE_CODE_ECHO_REQUEST 0x0080

#define ICMPV4_TYPE_CODE_ECHO_REPLY 0x0000
#define ICMPV6_TYPE_CODE_ECHO_REPLY 0x0081

#define ICMPV4_TYPE_CODE_NETWORK_UNREACHABLE 0x0003
#define ICMPV6_TYPE_CODE_NETWORK_UNREACHABLE 0x0001

#define ICMPV4_TYPE_CODE_ADDRESS_UNREACHABLE 0x0103
#define ICMPV6_TYPE_CODE_ADDRESS_UNREACHABLE 0x0301

#define ICMPV4_TYPE_CODE_PORT_UNREACHABLE 0x0303
#define ICMPV6_TYPE_CODE_PORT_UNREACHABLE 0x0401

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

typedef struct
{
    union
    {
        struct
        {
            uint8_t type;
            uint8_t code;
        };
        uint16_t type_code;
    };
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
        struct
        {
            uint16_t id;
            uint16_t seq;
        };
    };
} __attribute__((packed)) icmpv4_header_t;

typedef struct
{
    union
    {
        struct
        {
            uint8_t type;
            uint8_t code;
        };
        uint16_t type_code;
    };
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
        struct
        {
            uint16_t id;
            uint16_t seq;
        };
    };
} __attribute__((packed)) icmpv6_header_t;

typedef struct
{
    uint8_t next_header;
    uint8_t resevrved1;
    uint16_t offset_mf;
    uint32_t id;
} __attribute__((packed)) ipv6_fragment_header_t;

typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed)) udp_header_t;

typedef struct
{
    uint32_t header0[4];
    uint16_t checksum;
    uint16_t header1;
} __attribute__((packed)) tcp_header_t;

extern uint8_t local_prefix[16];
extern uint8_t remote_prefix[16];

static inline int get_version(void *pkt)
{
    ipv4_header_t *v4pkt = (ipv4_header_t *)pkt;
    return v4pkt->version_header_len >> 4;
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

static inline uint32_t ip_checksum_neg_partial(const void *buff, size_t len)
{
    uint32_t checksum = 0;
    const uint16_t *buff16 = (const uint16_t *)buff;
    for (int i = 0; i < len / sizeof(uint16_t); ++i)
    {
        checksum += ntohs(~buff16[i]);
    }
    if (len & 1) checksum += ~((const uint8_t *)buff)[len - 1] & 0xffff;
    return checksum;
}

static inline uint16_t ip_checksum_final(uint32_t checksum)
{
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
    return ~htons(checksum & 0xffff);
}

#endif // _TUN464_COMMON_H_
