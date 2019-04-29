#include "6to4.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common.h"

ssize_t v6_to_v4(ipv4_header_t *v4pkt, size_t v4len, const ipv6_header_t *v6pkt, size_t v6len,
                 size_t copy_len, int reverse)
{
    if (v6len < sizeof(ipv6_header_t)) return -5;
    if (v4len < sizeof(ipv4_header_t)) return -6;
    uint16_t payload_len = ntohs(v6pkt->payload_len);
    if (payload_len < copy_len) copy_len = payload_len;
    if (v6len < sizeof(ipv6_header_t) + copy_len) return -7;
    if (v4len < sizeof(ipv4_header_t) + copy_len) return -8;
    const uint8_t *dst_prefix = local_prefix, *src_prefix = remote_prefix;
    if (reverse)
    {
        dst_prefix = remote_prefix;
        src_prefix = local_prefix;
    }
    if (memcmp(v6pkt->dst_bytes, dst_prefix, PREFIX_BYTES) != 0) return -9;

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
        // Use CGN addresses. FIXME: new translation design needed
        v4pkt->src_bytes[0] = 100;
        v4pkt->src_bytes[1] = 0x40 | (v6pkt->src_bytes[7] & 0x3f);
        v4pkt->src_bytes[2] = v6pkt->src_bytes[14];
        v4pkt->src_bytes[3] = v6pkt->src_bytes[15];
    }
    memcpy(v4pkt->dst_bytes, v6pkt->dst_bytes + PREFIX_BYTES, HOST_BYTES);

    // Translate upper-layer protocol data.
    if (copy_len >= sizeof(icmpv4_header_t) && v6pkt->next_header == IPV6_NEXT_HEADER_ICMP)
    {
        // We are going to copy all of the payload, but this is an ICMP packet,
        // so we should translate it first.
#ifdef VERBOSE
        printf("  This is an ICMP packet.\n");
#endif
        int only_header = copy_len != payload_len;
        int ret = icmpv6_to_icmpv4((icmpv4_header_t *)(v4pkt + 1), v4len - sizeof(ipv4_header_t),
                                   (icmpv6_header_t *)(v6pkt + 1), v6len - sizeof(ipv6_header_t),
                                   v6pkt->src_bytes, v6pkt->dst_bytes,
                                   payload_len, only_header);
        if (ret <= 0) return ret;
        copy_len = ret;
        if (!only_header)
        {
            payload_len = ret;
            v4pkt->total_len = htons(sizeof(ipv4_header_t) + payload_len);
        }
        v4pkt->next_header = IPV4_NEXT_HEADER_ICMP;
    }
    else
    {
        // Just copy the payload.
        memcpy(v4pkt + 1, v6pkt + 1, copy_len);
    }

    // Calculate IPv4 header checksum.
    v4pkt->checksum = ip_checksum_final(ip_checksum_partial(v4pkt, sizeof(ipv4_header_t)));
    return sizeof(ipv4_header_t) + copy_len;
}

static inline int icmpv6_to_icmpv4_type_code(uint16_t type_code)
{
#define DO_TYPE_CODE(name) \
case ICMPV6_TYPE_CODE_##name: \
    return ICMPV4_TYPE_CODE_##name;
    switch (type_code)
    {
    DO_TYPE_CODE(TTL)
    DO_TYPE_CODE(NETWORK_UNREACHABLE)
    DO_TYPE_CODE(ADDRESS_UNREACHABLE)
    DO_TYPE_CODE(PORT_UNREACHABLE)
    default:
        return -1;
    }
#undef DO_TYPE_CODE
}

static inline ssize_t icmpv6_to_icmpv4_ip_payload(icmpv4_header_t *v4pkt, size_t v4len,
                                                  const icmpv6_header_t *v6pkt, size_t v6len)
{
    int ret;
    if ((ret = v6_to_v4((ipv4_header_t *)(v4pkt + 1), v4len - sizeof(icmpv4_header_t),
                        (ipv6_header_t *)(v6pkt + 1), v6len - sizeof(icmpv6_header_t), 8, 1)) <= 0)
    {
        return ret;
    }
    size_t len = sizeof(icmpv4_header_t) + ret;
    v4pkt->checksum = ip_checksum_final(ip_checksum_partial(v4pkt, len));
    return len;
}

static inline ssize_t icmpv6_to_icmpv4_data_payload(icmpv4_header_t *v4pkt, size_t v4len,
                                                    const icmpv6_header_t *v6pkt, size_t v6len,
                                                    const uint8_t *src_bytes, const uint8_t *dst_bytes,
                                                    uint16_t payload_len, int only_header)
{
    if (!only_header)
    {
        if (v4len < sizeof(icmpv4_header_t) + v6len - sizeof(icmpv6_header_t)) return -13;
        memcpy(v4pkt + 1, v6pkt + 1, v6len - sizeof(icmpv6_header_t));
    }
    // Incrementally update the checksum.
    uint32_t checksum = ntohs(~v6pkt->checksum);
    // src, dst -> 0
    checksum += ip_checksum_neg_partial(src_bytes, 16);
    checksum += ip_checksum_neg_partial(dst_bytes, 16);
    // type, code changed
    checksum += ~(((uint16_t)v6pkt->type << 8) | v6pkt->code) & 0xffff;
    checksum += (((uint16_t)v4pkt->type << 8) | v4pkt->code);
    // payload length -> 0
    checksum += ~payload_len & 0xffff;
    // next header -> 0
    checksum += ~IPV6_NEXT_HEADER_ICMP & 0xffff;
    v4pkt->checksum = ip_checksum_final(checksum);
    if (!only_header)
    {
        return sizeof(icmpv4_header_t) + v6len - sizeof(icmpv6_header_t);
    }
    else
    {
        return sizeof(icmpv4_header_t);
    }
}

ssize_t icmpv6_to_icmpv4(icmpv4_header_t *v4pkt, size_t v4len,
                         const icmpv6_header_t *v6pkt, size_t v6len,
                         const uint8_t *src_bytes, const uint8_t *dst_bytes,
                         uint16_t payload_len, int only_header)
{
    if (v6len < sizeof(icmpv6_header_t)) return -10;
    if (v4len < sizeof(icmpv4_header_t)) return -11;
    int new_type_code = icmpv6_to_icmpv4_type_code(v6pkt->type_code);
    if (new_type_code >= 0)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (generic error type %d code %d).\n",
               v6pkt->type, v6pkt->code);
#endif
        v4pkt->type_code = new_type_code & 0xffff;
        v4pkt->checksum = 0;
        v4pkt->rest = 0;
        return icmpv6_to_icmpv4_ip_payload(v4pkt, v4len, v6pkt, v6len);
    }
    if (v6pkt->type_code == ICMPV6_TYPE_CODE_TOO_BIG)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (too big).\n");
#endif
        v4pkt->type_code = ICMPV4_TYPE_CODE_TOO_BIG;
        v4pkt->checksum = 0;
        v4pkt->ununsed1 = 0;
        // Adjust MTU overhead.
        v4pkt->mtu = htons(ntohs(v6pkt->mtu) - sizeof(ipv6_header_t) + sizeof(ipv4_header_t));
        return icmpv6_to_icmpv4_ip_payload(v4pkt, v4len, v6pkt, v6len);
    }
    if (v6pkt->type_code == ICMPV6_TYPE_CODE_ECHO_REQUEST)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (echo request).\n");
#endif
        v4pkt->type_code = ICMPV4_TYPE_CODE_ECHO_REQUEST;
        v4pkt->checksum = 0;
        v4pkt->id = v6pkt->id;
        v4pkt->seq = v6pkt->seq;
        return icmpv6_to_icmpv4_data_payload(v4pkt, v4len, v6pkt, v6len,
                                             src_bytes, dst_bytes, payload_len, only_header);
    }
    if (v6pkt->type_code == ICMPV6_TYPE_CODE_ECHO_REPLY)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (echo reply).\n");
#endif
        v4pkt->type_code = ICMPV4_TYPE_CODE_ECHO_REPLY;
        v4pkt->checksum = 0;
        v4pkt->id = v6pkt->id;
        v4pkt->seq = v6pkt->seq;
        return icmpv6_to_icmpv4_data_payload(v4pkt, v4len, v6pkt, v6len,
                                             src_bytes, dst_bytes, payload_len, only_header);
    }
#if defined(VERBOSE) || defined(LOG_ERROR)
    printf("Unknown ICMP type %d code %d.\n", v6pkt->type, v6pkt->code);
#endif
    return -12;
}

