/*
 *  Copyright (C) 2007  Iain Wade <iwade@optusnet.com.au>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *I/O error, dev nbd0, sector 136 op 0x0:(READ) flags 0x80700 phys_seg 14 prio class 2
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <syslog.h>

//#include "queue.h"
#include <sys/queue.h>

#if USE_NBD
#include "nbd.h"
#endif

#include "psan.h"
#include "psan_wireformat.h"
#include "util.h"

#define UT_VERSION_NUM "0.8"
#define INTERNAL_BUF_SIZE 65536

#define DIE(...) do {               \
    syslog(LOG_ERR, __VA_ARGS__);   \
    err(EXIT_FAILURE, __VA_ARGS__); \
} while (0)

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) expression
#endif

#define _select(...) TEMP_FAILURE_RETRY(select(__VA_ARGS__))
#define _read(...) TEMP_FAILURE_RETRY(read(__VA_ARGS__))
#define _recv(...) TEMP_FAILURE_RETRY(recv(__VA_ARGS__))
#define _sendmsg(...) TEMP_FAILURE_RETRY(sendmsg(__VA_ARGS__))
#define _sendto(...) TEMP_FAILURE_RETRY(sendto(__VA_ARGS__))

const char *ut_build_str = UT_VERSION_NUM " " __DATE__ " " __TIME__;

struct outstanding_t {
    struct nbd_request *nbd;
    uint16_t seq;
    void *psan;
    int psan_len;
    struct timeval timeout;
    TAILQ_ENTRY(outstanding_t) entries;
};

static TAILQ_HEAD(, outstanding_t) outstanding = TAILQ_HEAD_INITIALIZER(outstanding);


void resubmit_outstanding(int sock, struct sockaddr_in *dest);
void record_outstanding(struct outstanding_t *out);
struct outstanding_t *remove_outstanding(uint16_t seq);

void record_outstanding(struct outstanding_t *out)
{
    gettimeofday(&out->timeout, NULL);

    /* 1 second timeout */
    out->timeout.tv_sec++;

    TAILQ_INSERT_TAIL(&outstanding, out, entries);
}

struct outstanding_t *remove_outstanding(uint16_t seq)
{
    struct outstanding_t *out;

    TAILQ_FOREACH(out, &outstanding, entries)
    {
    if (out->seq != seq)
        continue;

    TAILQ_REMOVE(&outstanding, out, entries);

    return out;
    }

    return NULL;
}

void resubmit_outstanding(int sock, struct sockaddr_in *dest)
{
    struct timeval now, timeout;
    gettimeofday(&now, NULL);

    /* 1 second timeout */
    timeout = now;
    timeout.tv_sec++;

    struct outstanding_t *out = TAILQ_FIRST(&outstanding);

    while (out)
    {
        struct outstanding_t *next = TAILQ_NEXT(out, entries);

        /* stop at first future timeout */
        if (timercmp(&out->timeout, &now, >))
            break;

        /* resubmit original request */
        if (_sendto(sock, out->psan, out->psan_len, 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
            err(EXIT_FAILURE, "sendto");

        /* update timeout and move entry to end of list */
        out->timeout = timeout;
        TAILQ_REMOVE(&outstanding, out, entries);
        TAILQ_INSERT_TAIL(&outstanding, out, entries);

        out = next;
    }
}
