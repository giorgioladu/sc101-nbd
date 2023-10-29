/*
 *  Copyright (C) 2007  Iain Wade <iwade@optusnet.com.au>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "ut.h"


int sock;
int debug = 0;
/* open NBD device */
int nbd_fd;


void usage(void)
{
    printf("\nUsage: ut [options] [command] [san_uuid] [block_devices]");
    printf("\nThe ut command is used to manage PSAN devices such as the Netgear SC101. ");
    printf("\n");
    printf("[options]\n");
    printf("\t-d Select the eth device connected at same net of the SAN disk.\n");
    printf("\t-D Enable debug mode.\n");
    printf("[command]\n");
     printf("\t listall | list ( Query available PSAN partitions. )\n");
     printf("\t attach ( Attach PSAN partition identified by partition-id to an NDB block device.)\n");
    printf("[san_uuid]\n");
    printf("\tSAN partition identified by partition-id to an NDB block device.\n");
    printf("[block_devices]\n");
    printf("\tNDB block device ( /dev/nbdN )\n");
    printf("------------------------------------------");
    printf("\n Version %s", ut_build_str);
    printf("\n KERNEL_BUFFER_SIZE %s", KERNEL_BUFFER_SIZE);
    printf("\n NET_BUFFER_SIZE %d", NET_BUFFER_SIZE);
     printf("\n------------------------------------------\n");
     printf("\n");
    exit(1);
}

void psan_listall(void)
{
    /* find all disks on the network */
    struct disks_t *disks;
    if (!(disks = psan_find_disks()))
    return;

    /* query each disk */
    struct disk_t *disk;
    SLIST_FOREACH(disk, disks, entries)
    {
    struct disk_info_t *disk_info = NULL;

    if (!(disk_info = psan_query_disk(&disk->root_addr)))
        goto cleanup_disk;

    fprintf(stdout, "===============================================================================\n");
    fprintf(stdout, "VERSION  : %-16s              ROOT IP ADDR : %-16s\n", disk_info->version, inet_ntoa(disk->root_addr.sin_addr));
    fprintf(stdout, "TOTAL(GB): %-6.2f                        # PARTITIONS : %d (  %-10s)\n", disk_info->total_size/1024.0/1024.0/1024.0, disk_info->partitions, disk_info->label);
    fprintf(stdout, "FREE (MB): %-6.0f\n", disk_info->free_size/1024.0/1024.0);

    for (int i = 1; i <= disk_info->partitions; i++)
    {
        struct part_info_t *part_info = NULL;
        struct part_addr_t *part = NULL;
        char *mirror="N";

        if (i == 1)
        {
        fprintf(stdout, "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
        fprintf(stdout, "PARTITION                                   LABEL       MIR    IP ADDR      SIZE (GB)\n");
        }

        if (!(part_info = psan_query_root(&disk->root_addr, i)))
        goto cleanup_part;

        if (!(part = psan_resolve_id(part_info->id)))
        goto cleanup_part;

        if (strstr(part_info->id,".m1")) //check mirror
        mirror="Y";


        fprintf(stdout, "%-40s %-15s %-5s %-15s %5.2f\n",
        part_info->id, part_info->label, mirror, inet_ntoa(part->part_addr.sin_addr), part_info->size/1024.0/1024.0/1024.0);


    cleanup_part:
        if (part)
        free_part_addr(part);
        if (part_info)
        free_part_info(part_info);
    }

    cleanup_disk:
    if (disk_info)
        free_disk_info(disk_info);
    }

    free_disks(disks);

    fprintf(stdout, "===============================================================================\n");
}

void psan_resolve(char *id)
{
    struct part_addr_t *res;

    if (!(res = psan_resolve_id(id)))
    return;

    fprintf(stdout, "%s\n", inet_ntoa(res->part_addr.sin_addr));
}

void psan_read(char *id, long long offset)
{
    /* resolve id to IP */
    struct part_addr_t *res;

    if (!(res = psan_resolve_id(id)))
    return;

    /* send 512 byte get request */
    uint16_t expected_seq = psan_next_seq();
    struct psan_get_t get = {
    .ctrl = { .cmd = PSAN_GET, .seq = htons(expected_seq), .len_power = 9 },
    .sector = htonl(offset >> 9),
    };
    size_t get_len = sizeof(struct psan_get_t);
    sendto(sock, (void *)&get, get_len, 0, (struct sockaddr *)&res->part_addr, sizeof(res->part_addr));

    struct timeval timeout = { .tv_sec = 10 };
    struct psan_get_response_t *ret = wait_for_packet(
    sock, PSAN_GET_RESPONSE, expected_seq, sizeof(struct psan_get_response_t)+512, &timeout, NULL, 0);

    /* dump */
    dump_hex(ret->buffer, 512);
}

void psan_write(char *id, long long offset, char *file)
{
    /* resolve id to IP */
    struct part_addr_t *res;

    if (!(res = psan_resolve_id(id)))
    return;

    /* open file */
    int fd;

    if ((fd = open(file, O_RDONLY)) < 0)
    err(EXIT_FAILURE, "open");

    /* make sure size is a multiple of 512b not greater than 2^15 */
    struct stat sb;

    if (fstat(fd, &sb) < 0)
    err(EXIT_FAILURE, "fstat");

    if (sb.st_size % 512 || sb.st_size > 32768)
    return;

    /* read file into buffer */
    char buf[sb.st_size];

    if (read(fd, buf, sizeof(buf)) != sizeof(buf))
    return;

    int power;

    for (power = 9; power <= 15; power++)
    if (sizeof(buf) == 1<<power)
        break;

    if (power == 16)
    errx(EXIT_FAILURE, "bad power: %d(length=%u)", power, (unsigned)sizeof(buf));

    /* build packet */
    uint16_t expected_seq = psan_next_seq();
    struct psan_put_t put = {
    .ctrl = { .cmd = PSAN_PUT, .seq = htons(expected_seq), .len_power = power },
    .sector = htonl(offset >> 9),
    };

    struct iovec iov[] = {
    { .iov_base = &put, .iov_len = sizeof(put) },
    { .iov_base = &buf, .iov_len = sizeof(buf) }
    };
    int iov_len = sizeof(iov)/sizeof(*iov);

    struct msghdr msghdr = {
    .msg_name    = &res->part_addr,
    .msg_namelen = sizeof(res->part_addr),
    .msg_iov     = iov,
    .msg_iovlen  = iov_len
    };

    /* send put request */
    sendmsg(sock, &msghdr, 0);

    struct timeval timeout = { .tv_sec = 10 };
    struct psan_put_response_t *ret = wait_for_packet(
    sock, PSAN_PUT_RESPONSE, expected_seq, sizeof(struct psan_put_response_t), &timeout, NULL, 0);

    fprintf(stderr, "%s\n", ret ? "OK" : "FAILED");
}

#if USE_NBD

void psan_attach_nbd(char *id, char *path)
{


    if ((nbd_fd = open(path, O_RDWR)) < 0)
    err(EXIT_FAILURE, "open");

    /* when the kernel does readahead or combines requests into blocks larger than 8kb, errors increase */
    char filename[PATH_MAX];
    char *device = rindex(path, '/');
    snprintf(filename, sizeof(filename), "/sys/block/%s/queue/max_sectors_kb", device);
    int sysfs;
    if ((sysfs = open(filename, O_RDWR)) >= 0)
    {
        if (write(sysfs, KERNEL_BUFFER_SIZE, sizeof(KERNEL_BUFFER_SIZE)-1) < 0)
          warn("write(sysfs, \"KERNEL_BUFFER_SIZE\", %lu)", sizeof(KERNEL_BUFFER_SIZE)-1);

        close(sysfs);
    }

    if ((nbd_fd = open(path, O_RDWR)) < 0)
      err(EXIT_FAILURE, "open");

    /* resolve id to IP */
    struct part_addr_t *res;

    if (!(res = psan_resolve_id(id)))
    errx(EXIT_FAILURE, "unable to resolve id: %s", id);

    /* fetch capacity information */
    struct part_info_t *part_info;

    if (!(part_info = psan_query_part(&res->part_addr)))
    errx(EXIT_FAILURE, "unable to query partition information");

    /* set size info on NBD device */
    int blocksize_power = 12;
    uint32_t size = (uint32_t)(part_info->size >> blocksize_power);

    if (ioctl(nbd_fd, NBD_SET_BLKSIZE, (unsigned long)(1 << blocksize_power)) < 0)
    err(EXIT_FAILURE, "ioctl(NBD_SET_BLKSIZE)");

    if (ioctl(nbd_fd, NBD_SET_SIZE_BLOCKS, size) < 0)
    err(EXIT_FAILURE, "ioctl(NBD_SET_SIZE_BLOCKS)");

    /* setup NBD proxy socket */
    int socks[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, socks) < 0)
    err(EXIT_FAILURE, "socketpair");

    if (ioctl(nbd_fd, NBD_SET_SOCK, socks[0]) < 0)
    err(EXIT_FAILURE, "ioctl(NBD_SET_SOCK)");

    if (!debug)
    if (daemon(0, 0) < 0)
        err(EXIT_FAILURE, "daemon(0, 0)");

    /* fork worker threads */
    pid_t pid;
    if ((pid = fork()) < 0)
    err(EXIT_FAILURE, "fork");

    /* parent */
    if (pid)
    {
        close(sock);
        close(socks[0]);
        close(socks[1]);

    if (ioctl(nbd_fd, NBD_DO_IT) < 0)
        err(EXIT_FAILURE, "ioctl(NBD_DO_IT)");

    if (ioctl(nbd_fd, NBD_CLEAR_QUE) < 0)
        warn("ioctl(NBD_CLEAR_QUE)");

    if (ioctl(nbd_fd, NBD_CLEAR_SOCK) < 0)
        warn("ioctl(NBD_CLEAR_SOCK)");

    return;
    }

    /* child */
    close(socks[0]);
    //close(nbd_fd);

    int max = socks[1] > sock ? socks[1] : sock;
    fd_set set;
    int ret;

    while(1)
    {
    struct timeval *timeout = NULL;
    struct timeval now;
    gettimeofday(&now, NULL);

    /* setup select timeout to handle resubmission */
        struct outstanding_t *out;

        if ((out = TAILQ_FIRST(&outstanding)))
        {
        static struct timeval next_timeout;
        double diff = tv2dbl(out->timeout) - tv2dbl(now);
        if (diff < 0.1) diff = 0.1;
        next_timeout = dbl2tv(diff);
        timeout = &next_timeout;
        }

    FD_ZERO(&set);
    FD_SET(socks[1], &set);
    FD_SET(sock, &set);

    if ((ret = _select(max+1, &set, NULL, NULL, timeout)) < 0)
        err(EXIT_FAILURE, "select");

    if (FD_ISSET(socks[1], &set)) //_read socks[1] and sendto sock !!
    {
        static char buf[INTERNAL_BUF_SIZE];//form 65536
        static int len = 0;
        if ((ret = _read(socks[1], &buf[len], sizeof(buf)-len)) <= 0) //necessary for transfert file e data
        err(EXIT_FAILURE, "read");

        len += ret;

        int pos = 0;

        while (len - pos >= sizeof(struct nbd_request))
        {
        struct nbd_request *nbd = copy(&buf[pos], sizeof(struct nbd_request));
        nbd->magic = ntohl(nbd->magic);
        nbd->type = ntohl(nbd->type);
        nbd->from = ntohll(nbd->from);
        nbd->len = ntohl(nbd->len);

        /* sanity check the request */
        if (nbd->magic != NBD_REQUEST_MAGIC) // 0x25609513
            DIE("wrong MAGIC");

        if (nbd->from & (512-1) || (nbd->from >> 9) >= UINT32_MAX)
            DIE("offset must be a 512b sector between 0 and 2TB %llu", nbd->from);

        if (nbd->len < 512 || nbd->len > 32768 || nbd->len & (nbd->len-1))
            DIE("size must be a power of two between 512 and 32768: %u", nbd->len);

        uint8_t power = 9;
        while ((1 << power) < nbd->len)
            power++;

        void *ptr;
        int ptr_len = 0;

        uint16_t seq = psan_next_seq();

        if (nbd->type == NBD_CMD_WRITE)
        {
            if (len - pos < nbd->len)
            {
            free(nbd);
            break;
            }

            struct psan_put_t *put;
            ptr_len = sizeof(struct psan_put_t) + nbd->len;
            if (!(ptr = put = malloc(ptr_len)))
                err(EXIT_FAILURE, "malloc");
            memset(ptr, 0, sizeof(struct psan_put_t));

            put->ctrl = (struct psan_ctrl_t){ .cmd = PSAN_PUT, .seq = htons(seq), .len_power = power };
            put->sector = htonl((uint32_t)(nbd->from >> 9));
            memcpy(put->buffer, &buf[pos+sizeof(struct nbd_request)], nbd->len);

            pos += sizeof(struct nbd_request) + nbd->len;
        }
        else if (nbd->type == NBD_CMD_READ)
        {
            struct psan_get_t *get;
            ptr_len = sizeof(struct psan_get_t);
            if (!(ptr = get = malloc(ptr_len)))
                err(EXIT_FAILURE, "malloc");
            memset(ptr, 0, sizeof(struct psan_get_t));

            get->ctrl = (struct psan_ctrl_t){ .cmd = PSAN_GET, .seq = htons(seq), .len_power = power };
            get->sector = htonl((uint32_t)(nbd->from >> 9));

            pos += sizeof(struct nbd_request);
        }
        else
            DIE("unknown operation");

        if ((ret = _sendto(sock, ptr, ptr_len, 0, &res->part_addr, sizeof(res->part_addr))) < 0) //send to sock!!
            err(EXIT_FAILURE, "sendto");

        record_outstanding(dup_struct(struct outstanding_t,
            .nbd      = nbd,
            .seq      = seq,
            .psan     = ptr,
            .psan_len = ptr_len,
        ));
        }

        /* move leftover fragment to beginning of buffer */
        if (pos < len)
        memmove(&buf[0], &buf[pos], len-pos);

        len -= pos;
    }

    if (FD_ISSET(sock, &set)) //_recv to sock and send to socks[1]
    {
        uint8_t buf[INTERNAL_BUF_SIZE];//form 65536

        if ((ret = _recv(sock, buf, sizeof(buf), 0)) < 0)
            err(EXIT_FAILURE, "recv");


        if (ret < sizeof(struct psan_ctrl_t))
            continue;

        struct psan_ctrl_t *ctrl = (struct psan_ctrl_t *)buf;
        struct outstanding_t *out;

        if (!(out = remove_outstanding(ntohs(ctrl->seq))))
            continue;

        int error = 1;

        if (out->nbd->type == NBD_CMD_READ  && ctrl->cmd == PSAN_GET_RESPONSE  && ret == sizeof(struct psan_get_response_t) + out->nbd->len)
            error = 0;
        else if (out->nbd->type == NBD_CMD_WRITE && ctrl->cmd == PSAN_PUT_RESPONSE)
            error = 0;

        /* XXX: this is a dodgy hack.
         * sometimes the SC101 responds with unexpected data,
         * i find that waiting a bit and resubmitting the exact same request works.
         * perhaps I should be doing some throttling?
         */
        if (error)
        {
                record_outstanding(out);
                continue;
        }

        struct nbd_reply reply = {
        .magic  = htonl(NBD_REPLY_MAGIC),
        .error  = htonl(error)
        };
        memcpy(reply.handle, out->nbd->handle, sizeof(out->nbd->handle));

        struct iovec iov[2];
        int iov_len = 0;

        iov[iov_len++] = (struct iovec){ .iov_base = &reply, .iov_len = sizeof(reply) };

        if (!error && ctrl->cmd == PSAN_GET_RESPONSE)
        iov[iov_len++] = (struct iovec){ .iov_base = &buf[sizeof(struct psan_get_response_t)], .iov_len = out->nbd->len };

        struct msghdr msghdr = {
        .msg_iov     = iov,
        .msg_iovlen  = iov_len
        };

        if ((ret = _sendmsg(socks[1], &msghdr, 0)) < 0) //send to "socks[1]" the message
        err(EXIT_FAILURE, "sendmsg");

        free(out->nbd);
        free(out->psan);
        free(out);
    }

    resubmit_outstanding(sock, &res->part_addr); //resubmit to "sock" outstanding
    }

    return;
}

/*void psan_detach_nbd( char *path)
{
    if (nbd_fd < 0 )
    err(EXIT_FAILURE, "not open");


    if (ioctl(nbd_fd, NBD_CLEAR_QUE) < 0)
        warn("ioctl(NBD_CLEAR_QUE)");

    if (ioctl(nbd_fd, NBD_CLEAR_SOCK) < 0)
        warn("ioctl(NBD_CLEAR_SOCK)");

    if (ioctl(nbd_fd, NBD_DISCONNECT) < 0)
        warn("ioctl(NBD_DISCONNECT)");


    close(sock);
    close( nbd_fd );

    exit( EXIT_SUCCESS );
}*/

#endif

int main(int argc, char *argv[])
{
    char *dev = NULL;
    char *cmd = NULL;
    int ch;

    while ((ch = getopt(argc, argv, "d:D")) != -1)
    {
    switch (ch) {
        case 'd':
        dev = optarg;
        break;
        case 'D':
        debug = 1;
        break;
        case '?':
        default:
        usage();
    }
    }

    psan_init(dev);

#define args (argc - optind)
    if (args < 1)
    usage();

    cmd = argv[optind++];

    if (!strcmp(cmd, "listall") && !args)
    psan_listall();
    else if (!strcmp(cmd, "list") && !args)
    psan_listall();
    else if (!strcmp(cmd, "resolve") && args == 1)
    psan_resolve(argv[optind]);
    else if (!strcmp(cmd, "read") && args == 2)
    psan_read(argv[optind], atoll(argv[optind+1]));
    else if (!strcmp(cmd, "write") && args == 3)
    psan_write(argv[optind], atoll(argv[optind+1]), argv[optind+2]);
#if USE_NBD
    else if (!strcmp(cmd, "attach") && args == 2)
    psan_attach_nbd(argv[optind], argv[optind+1]);
    /*else if (!strcmp(cmd, "detach") && args == 1)
    psan_detach_nbd(argv[optind]);*/
#endif
    else
    usage();

    return 0;
}
