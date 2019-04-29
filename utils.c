#include "utils.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>

#include "common.h"

void print_hex(void *buff, size_t len)
{
    char *ch = (char *)buff;
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02hhx ", ch[i]);
    }
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
