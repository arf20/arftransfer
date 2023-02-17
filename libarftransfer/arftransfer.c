#include "arftransfer.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

#include <zlib.h>

/* ====================== Private ====================== */
#define global static


global char *blockbuf = NULL;
global char *cmdbuf = NULL;
global char *statbuf = NULL;
global char *databuf = NULL;

global int lasterror = 0;
global int lastsyserror = 0;
global int lastzerror = 0;

const char *errorstr[] = {
    [AFT_OK] = "No error",
    [AFT_BPERR_VERSION] = "Version mismatch",
    "Unrecongnised block type",
    "Block size too big",
    "Unrecognised command",
    "Unrecognised status",
    "Cannot inflate, wrong block type",
    "Inflate error",
    "Deflate error",
    "Unable to create socket",
    "Unable to resolve host",
    "No IP address found for host",
    "Unable to connect",
    "Error receiving",
    "Error sending",
    "Error closing",
    "Error binding socket",
    "Error listening on socket",
    "Error accepting connection",
    "Unexpected wrong block type received",
    "Incorrect login"
};

/* zlib stuff */
#define windowBits 15
#define ENABLE_ZLIB_GZIP 32

/* Private util */
struct timespec diff_timespec(const struct timespec *time1,
    const struct timespec *time0)
{
    assert(time1);
    assert(time0);
    struct timespec diff = {.tv_sec = time1->tv_sec - time0->tv_sec,
      .tv_nsec = time1->tv_nsec - time0->tv_nsec};
    if (diff.tv_nsec < 0) {
        diff.tv_nsec += 1000000000;
        diff.tv_sec--;
    }
    return diff;
}

int
aft_send_block(int fd, type_t type, const char *data, dsize_t size) {
    block_header_t *header = (block_header_t*)blockbuf;
    header->type = type;
    header->size = size;
    if (data != NULL)
        memcpy(blockbuf + sizeof(block_header_t), data, size);

    if (send(fd, blockbuf, sizeof(block_header_t) + size, 0) < 0) {
        lasterror = AFT_SYSERR_SEND;
        lastsyserror = errno;
        return AFT_ERROR;
    }
    return AFT_OK;
}

int
aft_send_cmd(int fd, cmd_t cmd, const char *targ, dsize_t size) {
    command_header_t *header = (command_header_t*)cmdbuf;
    header->cmd = cmd;
    header->size = size;
    memcpy(cmdbuf + sizeof(command_header_t), targ, size);
    return aft_send_block(fd, AFT_TYPE_CMD, cmdbuf,
        size + sizeof(command_header_t));
}

int
aft_send_stat(int fd, stat_t stat, const char *data, dsize_t size) {
    status_header_t *header = (status_header_t*)statbuf;
    header->stat = stat;
    header->size = size;
    memcpy(statbuf + sizeof(status_header_t), data, size);
    return aft_send_block(fd, AFT_TYPE_STAT, statbuf,
        size + sizeof(status_header_t));
}



int
aft_recv_block(int fd, block_t *block) { // size or -1
    if (recv(fd, blockbuf, AFT_MAX_BLOCK_SIZE, 0) < 0) {
        lasterror = AFT_SYSERR_RECV;
        lastsyserror = errno;
        return AFT_ERROR;
    }
    block->header = *(block_header_t*)blockbuf;
    block->data = blockbuf + sizeof(block_header_t);

    return AFT_OK;
}

int
aft_check_block(const block_t *block) {
    if (block->header.version != AFT_VER) {
        lasterror = AFT_BPERR_VERSION;
        return AFT_ERROR;
    }

    if (!(block->header.type >= AFT_TYPE_PING &&
        block->header.type <= AFT_TYPE_CDATA))
    {
        lasterror = AFT_BPERR_TYPE;
        return AFT_ERROR;
    }

    if (block->header.size > AFT_MAX_BLOCK_SIZE + sizeof(status_header_t)) {
        lasterror = AFT_BPERR_SIZE;
        return AFT_ERROR;
    }

    return AFT_OK;
}

int
aft_inflate_cdatab(const block_t *cdatab, block_t *datab) {
    if (cdatab->header.type != AFT_TYPE_CDATA)
        return AFT_CBIERR_TYPE;
    
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.avail_in = (uInt)cdatab->header.size;
    zs.next_in = (Bytef*)cdatab->data;
    zs.avail_out = (uInt)datab->header.size;
    zs.next_out = (Bytef*)datab->data;

    if (inflateInit(&zs) != Z_OK) {
        lasterror = AFT_ZERR_INFLATE;
        return AFT_ERROR;
    }

    if (inflate(&zs, Z_FINISH)) {
        lasterror = AFT_ZERR_INFLATE;
        return AFT_ERROR;
    }

    if (inflateEnd(&zs)) {
        lasterror = AFT_ZERR_INFLATE;
        return AFT_ERROR;
    }

    return AFT_OK;
}

void
aft_parse_cmd(const char *data, dsize_t bsize, command_t *command) {
    command->header = *(command_header_t*)data;
    command->targ = (char*)data + sizeof(command_header_t);
}

void
aft_parse_stat(const char *data, dsize_t bsize, status_t *status) {
    status->header = *(status_header_t*)data;
    status->sdata = (char*)data + sizeof(status_header_t);
}

int
aft_recv_stat(int fd, status_t *status) {
    block_t statb = { 0 };

    if (aft_recv_block(fd, &statb) != AFT_OK) {
        lasterror = AFT_SYSERR_RECV;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    if (aft_check_block(&statb) != AFT_OK) {
        return AFT_ERROR;
    }

    if (statb.header.type != AFT_TYPE_STAT) {
        lasterror = AFT_PERR_TYPE;
        return AFT_ERROR;
    }

    aft_parse_stat(statb.data, statb.header.size, status);
}

int
aft_check_cmd(const command_t *command) {
    if (!(command->header.cmd >= AFT_CMD_NC &&
        command->header.cmd <= AFT_CMD_CLOSE))
    {
        lasterror = AFT_CPERR_CMD;
        return AFT_ERROR;
    }
    return AFT_OK;
}

int
aft_check_stat(const status_t *command) {
    if (!(command->header.stat >= AFT_STAT_NS &&
        command->header.stat <= AFT_STAT_ESYS))
    {
        lasterror = AFT_SPERR_STAT;
        return AFT_ERROR;
    }
    return AFT_OK;
}

/* ====================== Exports ====================== */

int
aft_init() {
    /* allocate buffers */
    if ((blockbuf = malloc(AFT_MAX_BLOCK_SIZE +
        sizeof(block_header_t))) == NULL)
        return AFT_ERROR;
    if ((cmdbuf = malloc(AFT_MAX_BLOCK_SIZE + sizeof(block_header_t) +
        sizeof(command_header_t))) == NULL)
        return AFT_ERROR;
    if ((statbuf = malloc(AFT_MAX_BLOCK_SIZE + sizeof(block_header_t) +
        sizeof(status_header_t))) == NULL)
        return AFT_ERROR;
    if ((databuf = malloc(AFT_MAX_BLOCK_SIZE)) == NULL)
        return AFT_ERROR;
    return AFT_OK;
}

void
aft_cleanup() {
    free(blockbuf);
    free(cmdbuf);
    free(statbuf);
    free(databuf);
}

int
aft_get_last_error() {
    return lasterror;
}

const char*
aft_get_last_error_str() {
    return errorstr[lasterror];
}

int
aft_get_last_sys_error() {
    return lastsyserror;
}

const char*
aft_get_last_sys_error_str() {
    return strerror(lastsyserror);
}

int
aft_close(int fd) {
    aft_send_cmd(fd, AFT_CMD_CLOSE, NULL, 0); /* error here is unimportant */
    if (close(fd) < 0) {
        lasterror = AFT_SYSERR_CLOSE;
        lastsyserror = errno;
        return AFT_ERROR;
    }
}

int
aft_send_data(int fd, const char *data, dsize_t size) {
    return aft_send_block(fd, AFT_TYPE_DATA, data, size);
}

int
aft_send_cdata(int fd, const char *data, dsize_t size) {
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    zs.avail_in = (uInt)size;
    zs.next_in = (Bytef*)data;
    zs.avail_out = (uInt)AFT_MAX_BLOCK_SIZE;
    zs.next_out = (Bytef*)databuf;

    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8,
        Z_DEFAULT_STRATEGY) != Z_OK)
    {
        lasterror = AFT_ZERR_DEFLATE;
        return AFT_ERROR;
    }

    if (deflate(&zs, Z_FINISH)) {
        lasterror = AFT_ZERR_DEFLATE;
        return AFT_ERROR;
    }

    if (deflateEnd(&zs)) {
        lasterror = AFT_ZERR_DEFLATE;
        return AFT_ERROR;
    }

    return aft_send_block(fd, AFT_TYPE_CDATA, databuf, zs.total_out);
}

int
aft_resolve(const char *host, struct addrinfo **addrs) {
    struct addrinfo hints = { 0 };

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if (getaddrinfo(host, NULL, &hints, addrs) < 0) {
        lasterror = AFT_SYSERR_RESOLV;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    return AFT_OK;
}

int
aft_get_sa_addr_str(const struct sockaddr *addr, char *str, size_t strlen)
{
    void *ptr;
    if (addr->sa_family == AF_INET)
        ptr = &((struct sockaddr_in*)addr)->sin_addr;
    else if (addr->sa_family == AF_INET6)
        ptr = &((struct sockaddr_in6*)addr)->sin6_addr;
    
    int r = inet_ntop(addr->sa_family, ptr, str, strlen) != NULL
        ? AFT_OK : AFT_ERROR;

    return r;
}

int
aft_get_ai_addr_str(const struct addrinfo *addr, char *str, size_t strlen,
    int flags)
{
    void *ptr;
    if (addr->ai_family == AF_INET)
        ptr = &((struct sockaddr_in*)addr->ai_addr)->sin_addr;
    else if (addr->ai_family == AF_INET6)
        ptr = &((struct sockaddr_in6*)addr->ai_addr)->sin6_addr;
    
    int r = inet_ntop(addr->ai_family, ptr, str, strlen) != NULL
        ? AFT_OK : AFT_ERROR;
    if (flags && (r != -1)) {
        strcat(str, " (");
        strcat(str, addr->ai_canonname);
        strcat(str, ")");
    }
    return r;
}

/* client functions */
int
aft_open(const struct addrinfo *addr, uint16_t port) {
    int fd;
    
    /* create socket */
    if ((fd = socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        lasterror = AFT_SYSERR_SOCKET;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    if (addr->ai_family == AF_INET)
        ((struct sockaddr_in*)addr->ai_addr)->sin_port = htons(port);
    else if (addr->ai_family == AF_INET6)
        ((struct sockaddr_in6*)addr->ai_addr)->sin6_port = htons(port);

    /* try connect */
    if (connect(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
        lasterror = AFT_SYSERR_CONNECT;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    return fd;
}

int
aft_open_host(const char *host, uint16_t port) {
    struct addrinfo *addr;

    if (aft_resolve(host, &addr) != AFT_OK)
        return AFT_ERROR;

    int fd = 0;
    while (addr) {
        if ((fd = aft_open(addr, port)) == AFT_OK)
            return fd;
        addr = addr->ai_next;
    }

    return AFT_ERROR;
}

int
aft_ping(int fd, struct timespec *rtt) {
    block_t echo = { 0 };
    struct timespec start;
    struct timespec end;

    /* send ping request */
    if (aft_send_block(fd, AFT_TYPE_PING, NULL, 0) != AFT_OK) {
        lasterror = AFT_SYSERR_SEND;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    /* wait for answer */
    clock_gettime(CLOCK_REALTIME, &start);
    if (aft_recv_block(fd, &echo) != AFT_OK) {
        lasterror = AFT_SYSERR_RECV;
        lastsyserror = errno;
        return AFT_ERROR;
    }
    clock_gettime(CLOCK_REALTIME, &end);

    aft_check_block(&echo);

    if (echo.header.type != AFT_TYPE_PING) {
        lasterror = AFT_PERR_TYPE;
        return AFT_ERROR;
    }

    *rtt = diff_timespec(&end, &start);
    return AFT_OK;
}

int
aft_login(int fd, const char *user, const char *passwd) {
    size_t userlen = strlen(user) + 1;
    size_t passwdlen = strlen(user) + 1;
    dsize_t arglen = userlen + passwdlen;
    char *targ = malloc(arglen);
    memcpy(targ, user, userlen);
    memcpy(targ + userlen, user, passwdlen);

    if (aft_send_cmd(fd, AFT_CMD_LOGIN, targ, arglen) != AFT_OK) {
        free(targ);
        lasterror = AFT_SYSERR_SEND;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    free(targ);

    status_t loginres = { 0 };
    if (aft_recv_stat(fd, &loginres) != AFT_OK) {
        return AFT_ERROR;
    }

    if (loginres.header.stat != AFT_STAT_LOGGED) {
        lasterror = AFT_ERR_LOGIN;
        return AFT_ERROR;
    }

    return AFT_OK;
}



/* Server functions */

int
aft_listen(struct addrinfo *addr, uint16_t port) {
    int fd = -1;
    /* Create socket */
    if ((fd = socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        lasterror = AFT_SYSERR_SOCKET;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    if (addr->ai_family == AF_INET)
        ((struct sockaddr_in*)addr->ai_addr)->sin_port = htons(port);
    else if (addr->ai_family == AF_INET6)
        ((struct sockaddr_in6*)addr->ai_addr)->sin6_port = htons(port);

    /* Bind socket */
    if (bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
        lasterror = AFT_SYSERR_BIND;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    /* Listen on socket */
    if (listen(fd, SOMAXCONN) < 0) {
        lasterror = AFT_SYSERR_LISTEN;
        lastsyserror = errno;
        return AFT_ERROR;
    }

    return fd;
}

int
aft_accept(int fd, struct sockaddr *sa, socklen_t *len) {
    return accept(fd, sa, len);
}
