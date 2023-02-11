#include "arftransfer.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>

#include <zlib.h>

/* private */
char *blockbuf;
char *cmdbuf;
char *statbuf;
char *databuf;

/* zlib stuff */
#define windowBits 15
#define ENABLE_ZLIB_GZIP 32

int
aft_init() {
    /* allocate buffers */
    blockbuf = malloc(AFT_MAX_BLOCK_SIZE + sizeof(block_header_t));
    cmdbuf = malloc(AFT_MAX_BLOCK_SIZE + sizeof(block_header_t) + sizeof(command_header_t));
    statbuf = malloc(AFT_MAX_BLOCK_SIZE + sizeof(block_header_t) + sizeof(status_header_t));
    databuf = malloc(AFT_MAX_BLOCK_SIZE);
}

int
aft_send_block(int fd, type_t type, const char *data, dsize_t size) {
    block_header_t *header = (block_header_t*)blockbuf;
    header->type = type;
    header->size = size;
    memcpy(blockbuf + sizeof(block_header_t), data, size);
    return send(fd, blockbuf, size + sizeof(block_header_t), 0);
}

int
aft_send_cmd(int fd, cmd_t cmd, const char *targ, dsize_t size) {
    command_header_t *header = (command_header_t*)cmdbuf;
    header->cmd = cmd;
    header->size = size;
    memcpy(cmdbuf + sizeof(command_header_t), targ, size);
    return aft_send_block(fd, AFT_TYPE_CMD, size + sizeof(command_header_t), 0);
}

int
aft_send_stat(int fd, stat_t stat, const char *data, dsize_t size) {
    status_header_t *header = (status_header_t*)statbuf;
    header->stat = stat;
    header->size = size;
    memcpy(statbuf + sizeof(status_header_t), data, size);
    return aft_send_block(fd, AFT_TYPE_STAT, size + sizeof(status_header_t), 0);
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

    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
    deflate(&zs, Z_FINISH);
    deflateEnd(&zs);

    return aft_send_block(fd, AFT_TYPE_CDATA, databuf, zs.total_out);
}

int
aft_recv_block(int fd, block_t *block) { // size or -1
    int res = recv(fd, blockbuf, AFT_MAX_BLOCK_SIZE, 0);
    block->header = *(block_header_t*)blockbuf;
    block->data = blockbuf + sizeof(block_header_t);
    return res;
}

int
aft_check_block(const block_t *block) {
    if (block->header.version != AFT_VER)
        return AFT_BPERR_VERSION;

    if (!(block->header.type >= AFT_TYPE_PING && block->header.type <= AFT_TYPE_CDATA))
        return AFT_BPERR_TYPE;

    if (block->header.size > AFT_MAX_BLOCK_SIZE + sizeof(status_header_t))
        return AFT_BPERR_SIZE;
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

    inflateInit(&zs);
    inflate(&zs, Z_FINISH);
    inflateEnd(&zs);
}

int
aft_parse_cmd(const char *data, dsize_t bsize, command_t *command) { // size of arg or -1
    command->header = *(command_header_t*)data;
    command->targ = data + sizeof(command_header_t);
}

int
aft_parse_stat(const char *data, dsize_t bsize, status_t *status) { // size of data or -1
    status->header = *(status_header_t*)data;
    status->sdata = data + sizeof(status_header_t);
}

int
aft_check_cmd(const command_t *command) {
    if (!(command->header.cmd >= AFT_CMD_NC && command->header.cmd <= AFT_CMD_CLOSE))
        return AFT_CPERR_CMD;
}

int
aft_check_stat(const status_t *command) {
    if (!(command->header.stat >= AFT_STAT_NS && command->header.stat <= AFT_STAT_ESYS))
        return AFT_SPERR_STAT;
}
