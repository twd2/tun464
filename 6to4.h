#ifndef _TUN464_6TO4_H_
#define _TUN464_6TO4_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "common.h"

ssize_t v6_to_v4(ipv4_header_t *v4pkt, size_t v4len, const ipv6_header_t *v6pkt, size_t v6len,
                 size_t copy_len, int reverse);

ssize_t icmpv6_to_icmpv4(icmpv4_header_t *v4pkt, size_t v4len,
                         const icmpv6_header_t *v6pkt, size_t v6len,
                         const uint8_t *src_bytes, const uint8_t *dst_bytes,
                         uint16_t payload_len, int only_header);

#endif // _TUN464_6TO4_H_
