#include "4to6.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common.h"

ssize_t v4_to_v6(ipv6_header_t *v6pkt, size_t v6len, const ipv4_header_t *v4pkt, size_t v4len,
                 size_t copy_len, int reverse)
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
    const uint8_t *src_prefix = local_prefix, *dst_prefix = remote_prefix;
    if (reverse)
    {
        src_prefix = remote_prefix;
        dst_prefix = local_prefix;
    }
    memcpy(v6pkt->src_bytes, src_prefix, PREFIX_BYTES);
    memcpy(v6pkt->src_bytes + PREFIX_BYTES, v4pkt->src_bytes, HOST_BYTES);
    memcpy(v6pkt->dst_bytes, dst_prefix, PREFIX_BYTES);
    memcpy(v6pkt->dst_bytes + PREFIX_BYTES, v4pkt->dst_bytes, HOST_BYTES);

    // Translate upper-layer protocol data.
    if (copy_len >= sizeof(icmpv6_header_t) && v4pkt->next_header == IPV4_NEXT_HEADER_ICMP)
    {
        // We are going to copy all of the payload, but this is an ICMP packet,
        // so we should translate it.
#ifdef VERBOSE
        printf("  This is an ICMP packet.\n");
#endif
        int only_header = copy_len != payload_len || copy_len == sizeof(icmpv6_header_t);
        int ret = icmpv4_to_icmpv6((icmpv6_header_t *)(v6pkt + 1), v6len - sizeof(ipv6_header_t),
                                   (icmpv4_header_t *)((uint8_t *)v4pkt + v4header_len),
                                   v4len - v4header_len,
                                   v6pkt->src_bytes, v6pkt->dst_bytes,
                                   payload_len, only_header);
        if (ret <= 0) return ret;
        copy_len = ret;
        if (!only_header)
        {
            payload_len = ret;
            v6pkt->payload_len = htons(payload_len);
        }
        v6pkt->next_header = IPV6_NEXT_HEADER_ICMP;
    }
    else
    {
        // Just copy the payload.
        memcpy(v6pkt + 1, (uint8_t *)v4pkt + v4header_len, copy_len);
    }

    return sizeof(ipv6_header_t) + copy_len;
}

static inline int icmpv4_to_icmpv6_type_code(uint16_t type_code)
{
#define DO_TYPE_CODE(name) \
case ICMPV4_TYPE_CODE_##name: \
    return ICMPV6_TYPE_CODE_##name;
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

static inline ssize_t icmpv4_to_icmpv6_ip_payload(icmpv6_header_t *v6pkt, size_t v6len,
                                                  const icmpv4_header_t *v4pkt, size_t v4len,
                                                  const uint8_t *src_bytes, const uint8_t *dst_bytes)
{
    int ret;
    if ((ret = v4_to_v6((ipv6_header_t *)(v6pkt + 1), v6len - sizeof(icmpv6_header_t),
                        (ipv4_header_t *)(v4pkt + 1), v4len - sizeof(icmpv4_header_t), 8, 1)) <= 0)
    {
        return ret;
    }
    size_t len = sizeof(icmpv6_header_t) + ret;
    uint32_t checksum = ip_checksum_partial(src_bytes, 16) + ip_checksum_partial(dst_bytes, 16);
    checksum += (len >> 16) + (len & 0xffff);
    checksum += IPV6_NEXT_HEADER_ICMP;
    checksum += ip_checksum_partial(v6pkt, len);
    v6pkt->checksum = ip_checksum_final(checksum);
    return len;
}

static inline ssize_t icmpv4_to_icmpv6_data_payload(icmpv6_header_t *v6pkt, size_t v6len,
                                                    const icmpv4_header_t *v4pkt, size_t v4len,
                                                    const uint8_t *src_bytes, const uint8_t *dst_bytes,
                                                    uint16_t payload_len, int only_header)
{
    if (!only_header)
    {
        if (v6len < sizeof(icmpv6_header_t) + v4len - sizeof(icmpv4_header_t)) return -17;
        memcpy(v6pkt + 1, v4pkt + 1, v4len - sizeof(icmpv4_header_t));
    }
    // Incrementally update the checksum.
    uint32_t checksum = ntohs(~v4pkt->checksum);
    // 0 -> src, dst
    checksum += ip_checksum_partial(src_bytes, 16);
    checksum += ip_checksum_partial(dst_bytes, 16);
    // type, code changed
    checksum += ~(((uint16_t)v4pkt->type << 8) | v4pkt->code) & 0xffff;
    checksum += (((uint16_t)v6pkt->type << 8) | v6pkt->code);
    // 0 -> payload length
    checksum += payload_len;
    // 0 -> next header
    checksum += IPV6_NEXT_HEADER_ICMP;
    v6pkt->checksum = ip_checksum_final(checksum);
    if (!only_header)
    {
        return sizeof(icmpv6_header_t) + v4len - sizeof(icmpv4_header_t);
    }
    else
    {
        return sizeof(icmpv6_header_t);
    }
}

ssize_t icmpv4_to_icmpv6(icmpv6_header_t *v6pkt, size_t v6len,
                         const icmpv4_header_t *v4pkt, size_t v4len,
                         const uint8_t *src_bytes, const uint8_t *dst_bytes,
                         uint16_t payload_len, int only_header)
{
    if (v4len < sizeof(icmpv4_header_t)) return -14;
    if (v6len < sizeof(icmpv6_header_t)) return -15;
    int new_type_code = icmpv4_to_icmpv6_type_code(v4pkt->type_code);
    if (new_type_code >= 0)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (generic error type %d code %d).\n",
               v4pkt->type, v4pkt->code);
#endif
        v6pkt->type_code = new_type_code & 0xffff;
        v6pkt->checksum = 0;
        v6pkt->rest = 0;
        return icmpv4_to_icmpv6_ip_payload(v6pkt, v6len, v4pkt, v4len, src_bytes, dst_bytes);
    }
    if (v4pkt->type_code == ICMPV4_TYPE_CODE_TOO_BIG)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (too big).\n");
#endif
        v6pkt->type_code = ICMPV6_TYPE_CODE_TOO_BIG;
        v6pkt->checksum = 0;
        v6pkt->ununsed1 = 0;
        // Adjust MTU overhead.
        v6pkt->mtu = htons(ntohs(v4pkt->mtu) - sizeof(ipv4_header_t) + sizeof(ipv6_header_t));
        return icmpv4_to_icmpv6_ip_payload(v6pkt, v6len, v4pkt, v4len, src_bytes, dst_bytes);
    }
    if (v4pkt->type_code == ICMPV4_TYPE_CODE_ECHO_REQUEST)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (echo request).\n");
#endif
        v6pkt->type_code = ICMPV6_TYPE_CODE_ECHO_REQUEST;
        v6pkt->checksum = 0;
        v6pkt->id = v4pkt->id;
        v6pkt->seq = v4pkt->seq;
        return icmpv4_to_icmpv6_data_payload(v6pkt, v6len, v4pkt, v4len,
                                             src_bytes, dst_bytes, payload_len, only_header);
    }
    if (v4pkt->type_code == ICMPV4_TYPE_CODE_ECHO_REPLY)
    {
#ifdef VERBOSE
        printf("  This is an ICMP packet (echo reply).\n");
#endif
        v6pkt->type_code = ICMPV6_TYPE_CODE_ECHO_REPLY;
        v6pkt->checksum = 0;
        v6pkt->id = v4pkt->id;
        v6pkt->seq = v4pkt->seq;
        return icmpv4_to_icmpv6_data_payload(v6pkt, v6len, v4pkt, v4len,
                                             src_bytes, dst_bytes, payload_len, only_header);
    }
#if defined(VERBOSE) || defined(LOG_ERROR)
    printf("Unknown ICMP type %d code %d.\n", v4pkt->type, v4pkt->code);
#endif
    return -16;
}
