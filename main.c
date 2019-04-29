#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "utils.h"
#include "4to6.h"
#include "6to4.h"

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
                                       (ipv4_header_t *)buffer, len, -1, 0);
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
#if defined(VERBOSE) || defined(LOG_ERROR)
#ifndef VERBOSE
                print_ipv4_packet((ipv4_header_t *)buffer);
#endif
                printf("  translation failed: %ld\n", new_len);
                print_hex(buffer, len);
                printf("\n");
#endif
            }
        }
        if (version == 6)
        {
#ifdef VERBOSE
            print_ipv6_packet((ipv6_header_t *)buffer);
#endif
            ssize_t new_len = v6_to_v4((ipv4_header_t *)new_buffer, BUFFER_SIZE,
                                       (ipv6_header_t *)buffer, len, -1, 0);
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
#if defined(VERBOSE) || defined(LOG_ERROR)
#ifndef VERBOSE
                print_ipv6_packet((ipv6_header_t *)buffer);
#endif
                printf("  translation failed: %ld\n", new_len);
                print_hex(buffer, len);
                printf("\n");
#endif
            }
        }
    }
    return 0;
}
