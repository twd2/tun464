#ifndef _TUN464_UTILS_H_
#define _TUN464_UTILS_H_

#include <stddef.h>

#include "common.h"

void print_hex(void *buff, size_t len);
void print_ipv4_packet(ipv4_header_t *v4pkt);
void print_ipv6_packet(ipv6_header_t *v6pkt);

#endif // _TUN464_UTILS_H_
