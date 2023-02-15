#ifndef _ARFTRANSFER_H
#define _ARFTRANSFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>

#define AFT_VER 0x13

#define AFT_MAX_BLOCK_SIZE      0xffff

/* Block types */
/*   Common between server and client */
#define AFT_TYPE_PING           0x00
#define AFT_TYPE_CMD            0x01
#define AFT_TYPE_STAT           0x01
#define AFT_TYPE_DATA           0x02
#define AFT_TYPE_CDATA          0x03

/* Command types */
enum {
    AFT_CMD_NC,
    AFT_CMD_LOGIN,
    AFT_CMD_PWD,
    AFT_CMD_LS,
    AFT_CMD_CD,
    AFT_CMD_GET,
    AFT_CMD_PUT,
    AFT_CMD_ENCRYPT,
    AFT_CMD_CLOSE
};
/* Status types */
enum {
    AFT_STAT_NS,
    AFT_STAT_LOGGED,
    AFT_STAT_PWDD,
    AFT_STAT_LSD,
    AFT_STAT_ACK,
    AFT_STAT_EANON,
    AFT_STAT_ELOGIN,
    AFT_STAT_ENODIR,
    AFT_STAT_ENOFILE,
    AFT_STAT_EACCESS,
    AFT_STAT_ESYS
};

/* Types */
typedef uint8_t type_t;
typedef uint8_t ver_t;
typedef uint16_t dsize_t;
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
enum {
    AFT_ERROR = -1,
    AFT_OK,
/* Block parse errors */
    AFT_BPERR_VERSION,       /* Block version mismatch */
    AFT_BPERR_TYPE,          /* Unrecongnised block type */
    AFT_BPERR_SIZE,          /* Block Size too big */
/* Command parse errors */
    AFT_CPERR_CMD,           /* Unrecognised command */
/* Status parse errors */
    AFT_SPERR_STAT,          /* Unrecognised status */
/* Compressing errors */
    AFT_CBIERR_TYPE,         /* Cannot inflate - wrong block type */
    AFT_ZERR_INFLATE,        /* Inflate error */
    AFT_ZERR_DEFLATE,        /* Deflate error */
/* Socket errors */
    AFT_SYSERR_SOCKET,       /* Unable to create socket */
    AFT_SYSERR_RESOLV,       /* Unable to resolve host */
    AFT_SYSERR_NOIP,         /* No IP address found for host */
    AFT_SYSERR_CONNECT,      /* Unable to connect */
    AFT_SYSERR_RECV,         /* Error receiving */
    AFT_SYSERR_SEND,         /* Error sending */
    AFT_SYSERR_CLOSE,        /* Error closing */
/* Protocol errors */
    AFT_PERR_TYPE,           /* Unexpected wrong block type received */

/* Normal errors */
    AFT_ERR_LOGIN            /* Incorrect login */
};

/* Exports */
int aft_init();
void aft_cleanup();
int aft_get_last_error();
const char *aft_get_last_error_str();
int aft_get_last_sys_error();
const char* aft_get_last_sys_error_str();
int aft_close();
int aft_send_data(int fd, const char *data, dsize_t size);
int aft_send_cdata(int fd, const char *data, dsize_t size);
/* Client functions */
int aft_resolve(const char *host, struct addrinfo **addrs);
int aft_get_addr_str(const struct addrinfo *addr, char *str, size_t strlen);
int aft_open(const struct addrinfo *addr, uint16_t port);
int aft_open_host(const char *host, uint16_t port);
int aft_ping(int fd, struct timespec *rtt);
int aft_login(int fd, const char *user, const char *passwd);

#ifdef __cplusplus
}
#endif

#endif /* _ARFTRANSFER_H */
