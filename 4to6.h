#ifndef _TUN464_4TO6_H_
#define _TUN464_4TO6_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "common.h"

ssize_t v4_to_v6(ipv6_header_t *v6pkt, size_t v6len, const ipv4_header_t *v4pkt, size_t v4len,
                 size_t copy_len, int reverse);

ssize_t icmpv4_to_icmpv6(icmpv6_header_t *v6pkt, size_t v6len,
                         const icmpv4_header_t *v4pkt, size_t v4len,
                         const uint8_t *src_bytes, const uint8_t *dst_bytes,
                         uint16_t payload_len, int only_header);

#endif // _TUN464_4TO6_H_
