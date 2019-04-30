#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
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
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
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

static int v4tun_fd, v6tun_fd;

static void *v4entry(void *_)
{
    char *buffer = guarded_malloc(BUFFER_SIZE), *new_buffer = guarded_malloc(BUFFER_SIZE);
    while (1)
    {
        ssize_t len = read(v4tun_fd, buffer, BUFFER_SIZE);
        if (len <= 0)
        {
            perror("Reading from interface for IPv4");
            exit(1);
        }

        int version = get_version(buffer);
        if (version != 4) continue;
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
            ssize_t ret = write(v6tun_fd, new_buffer, new_len);
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
    return NULL;
}

static void *v6entry(void *_)
{
    char *buffer = guarded_malloc(BUFFER_SIZE), *new_buffer = guarded_malloc(BUFFER_SIZE);
    while (1)
    {
        ssize_t len = read(v6tun_fd, buffer, BUFFER_SIZE);
        if (len <= 0)
        {
            perror("Reading from interface for IPv6");
            exit(1);
        }

        int version = get_version(buffer);
        if (version != 6) continue;
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
            ssize_t ret = write(v6tun_fd, new_buffer, new_len);
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
    return NULL;
}

int main(int argc, const char **argv)
{
    if (argc < 2)
    {
        printf("Usage: %s dev_name [local_prefix remote_prefix]\n", argv[0]);
        return 1;
    }

    const char *name = argv[1];
    if (strlen(name) + 5 + 1 > IFNAMSIZ)
    {
        printf("dev_name is too long.\n");
        return 1;
    }
    char v4name[IFNAMSIZ], v6name[IFNAMSIZ];
    strcpy(v4name, name);
    strcpy(v6name, name);
    strcat(v4name, "-ipv4");
    strcat(v6name, "-ipv6");
    printf("Using %s for IPv4 and %s for IPv6.\n", v4name, v6name);

    if (argc >= 4)
    {
        inet_pton(AF_INET6, argv[2], local_prefix);
        inet_pton(AF_INET6, argv[3], remote_prefix);
        printf("Local prefix: %s\n", argv[2]);
        printf("Remote prefix: %s\n", argv[3]);
    }
    else
    {
        inet_pton(AF_INET6, LOCAL_PREFIX, local_prefix);
        inet_pton(AF_INET6, REMOTE_PREFIX, remote_prefix);
        printf("Local prefix: %s\n", LOCAL_PREFIX);
        printf("Remote prefix: %s\n", REMOTE_PREFIX);
    }

    if ((v4tun_fd = tun_alloc(v4name, IFF_TUN | IFF_NO_PI)) < 0)
    {
        perror("Allocating interface for IPv4");
        exit(1);
    }

    if ((v6tun_fd = tun_alloc(v6name, IFF_TUN | IFF_NO_PI)) < 0)
    {
        perror("Allocating interface for IPv6");
        exit(1);
    }

    setuid(65534);
    setgid(65534);
    seteuid(65534);
    setegid(65534);

    pthread_t v4thread, v6thread;
    pthread_create(&v4thread, NULL, v4entry, NULL);
    pthread_create(&v6thread, NULL, v6entry, NULL);
    pthread_join(v4thread, NULL);
    pthread_join(v6thread, NULL);

    return 0;
}
