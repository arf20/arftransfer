#ifndef _ARFTRANSFER_H
#define _ARFTRANSFER_H

#include <stdint.h>
#include <sys/types.h>

#define AFT_VER 0x12

#define AFT_MAX_BLOCK_SIZE      0xffff

/* Block types */
/*   Common between server and client */
#define AFT_TYPE_PING    0x00
#define AFT_TYPE_CMD     0x01
#define AFT_TYPE_STAT    0x01
#define AFT_TYPE_DATA    0x02
#define AFT_TYPE_CDATA   0x03


/* Command types */
#define AFT_CMD_NC              0x00
#define AFT_CMD_LOGIN           0x01
#define AFT_CMD_PWD             0x02
#define AFT_CMD_LS              0x03
#define AFT_CMD_CD              0x04
#define AFT_CMD_GET             0x05
#define AFT_CMD_PUT             0x06
#define AFT_CMD_ENCRYPT         0x07
#define AFT_CMD_CLOSE           0x08
/* Status types */
#define AFT_STAT_NS             0x00
#define AFT_STAT_LOGGED         0x01
#define AFT_STAT_PWDD           0x02
#define AFT_STAT_LSD            0x03
#define AFT_STAT_ACK            0x04
#define AFT_STAT_EANON          0x05
#define AFT_STAT_ELOGIN         0x06
#define AFT_STAT_ENODIR         0x07
#define AFT_STAT_ENOFILE        0x08
#define AFT_STAT_EACCESS        0x09
#define AFT_STAT_ESYS           0x0a

/* Types */
typedef uint8_t type_t;
typedef uint8_t ver_t;
typedef uint8_t dsize_t;
typedef uint8_t cmd_t;
typedef uint8_t stat_t;

/* Headers */
typedef struct block_header_s {
    type_t type;
    ver_t version;
    dsize_t size;
} block_header_t;

typedef struct block_s {
    block_header_t header;
    const uint8_t *data;
} block_t;

typedef struct command_header_s {
    cmd_t cmd;
    dsize_t size;
    uint8_t zero;   /* reserved */
} command_header_t;

typedef struct command_s {
    command_header_t header;
    uint8_t *targ;
} command_t;

typedef struct status_header_s {
    stat_t stat;
    dsize_t size;
    uint8_t zero;   /* reserved */
} status_header_t;

typedef struct status_s {
    status_header_t header;
    uint8_t *sdata;
} status_t;

typedef struct dir_entry_s {
    mode_t mode;    /* uint32_t */
    uid_t uid;      /* uint32_t */
    gid_t gid;      /* uint32_t */
    size_t size;    /* uint64_t */
    time_t mtime;   /* uint64_t */
    char name[256]; /* last char is NUL */
} dir_entry_t;

typedef struct dir_s {
    dir_entry_t *entries;
    size_t count;
} dir_t;

/* Implementation errors */
/* Block parse errors */
#define AFT_BPERR_VERSION   1   /* Version mismatch */
#define AFT_BPERR_TYPE      2   /* Unrecongnised type mismatch */
#define AFT_BPERR_SIZE      3   /* Size too big */
#define AFT_CBIERR_TYPE     4   /* Cannot inflate - wrong block type */
/* Command parse errors */
#define AFT_CPERR_CMD       5   /* Unrecognised command */
/* Status parse errors */
#define AFT_SPERR_STAT      6   /* Unrecognised status */

#endif /* _ARFTRANSFER_H */
