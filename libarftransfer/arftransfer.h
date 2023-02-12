#ifndef _ARFTRANSFER_H
#define _ARFTRANSFER_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define AFT_VER 0x13

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
#define AFT_OK              0
#define AFT_ERROR           -1
/* Block parse errors */
#define AFT_BPERR_VERSION   1    /* Block version mismatch */
#define AFT_BPERR_TYPE      2    /* Unrecongnised block type */
#define AFT_BPERR_SIZE      3    /* Block Size too big */
/* Command parse errors */
#define AFT_CPERR_CMD       4    /* Unrecognised command */
/* Status parse errors */
#define AFT_SPERR_STAT      5    /* Unrecognised status */
/* Compressing errors */
#define AFT_CBIERR_TYPE     6    /* Cannot inflate - wrong block type */
#define AFT_ZERR_INFLATE    7    /* Inflate error */
#define AFT_ZERR_DEFLATE    8    /* Deflate error */
/* Socket errors */
#define AFT_SYSERR_SOCKET   9    /* Unable to create socket */
#define AFT_SYSERR_RESOLV   10   /* Unable to resolve host */
#define AFT_SYSERR_NOIP     11   /* No IP address found for host */
#define AFT_SYSERR_CONNECT  12   /* Unable to connect */
#define AFT_SYSERR_RECV     13   /* Error receiving */
#define AFT_SYSERR_SEND     14   /* Error sending */
#define AFT_SYSERR_CLOSE    15   /* Error closing */
/* Protocol errors */
#define AFT_PERR_TYPE       16   /* Unexpected wrong block type received */

/* Normal errors */
#define AFT_ERR_LOGIN       17   /* Incorrect login */

/* Exports */
int aft_init();
int aft_get_last_error();
const char *aft_get_last_error_str();
int aft_close();
/* Client functions */
int aft_ping(int fd, struct timespec *rtt);

#endif /* _ARFTRANSFER_H */
