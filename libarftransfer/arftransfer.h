#ifndef _ARFTRANSFER_H
#define _ARFTRANSFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>

#define AFT_VER 0x14

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
    AFT_CMD_RM,
    AFT_CMD_ENCRYPT
};
/* Status types */
enum {
    AFT_STAT_NS,
    AFT_STAT_ACK,
    AFT_STAT_PWDD,
    AFT_STAT_LSD,
    AFT_STAT_ELOGIN,
    AFT_STAT_EANON,
    AFT_STAT_ENODIR,
    AFT_STAT_ENOFILE,
    AFT_STAT_EACCESS,
    AFT_STAT_ESYS,
    AFT_STAT_ENOTIMPL
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
} __attribute__((packed)) block_header_t;

typedef struct block_s {
    block_header_t header;
    const uint8_t *data;
} block_t;

typedef struct command_header_s {
    cmd_t cmd;
    dsize_t size;
    uint8_t zero;   /* reserved */
} __attribute__((packed)) command_header_t;

typedef struct command_s {
    command_header_t header;
    uint8_t *targ;
} command_t;

typedef struct status_header_s {
    stat_t stat;
    dsize_t size;
    uint8_t zero;   /* reserved */
} __attribute__((packed)) status_header_t;

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
} __attribute__((packed)) dir_entry_t;

typedef struct dir_s {
    dir_entry_t *entries;
    size_t count;
} dir_t;

#define AFT_MAX_BLOCK_DATA_SIZE      0xffff
#define AFT_MAX_BLOCK_SIZE           (AFT_MAX_BLOCK_DATA_SIZE + sizeof(block_header_t))
#define AFT_MAX_CMD_DATA_SIZE        (AFT_MAX_BLOCK_DATA_SIZE - sizeof(command_header_t))
#define AFT_MAX_STAT_DATA_SIZE       (AFT_MAX_BLOCK_DATA_SIZE - sizeof(status_header_t))

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
    AFT_CPERR_SIZE,          /* Command data too big */
/* Status parse errors */
    AFT_SPERR_STAT,          /* Unrecognised status */
    AFT_SPERR_SIZE,          /* Status data too big*/
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

    AFT_SYSERR_BIND,         /* Error binding socket */
    AFT_SYSERR_LISTEN,       /* Error listening on socket */
    AFT_SYSERR_ACCEPT,       /* Error accepting connection */

    AFT_SYSERR_CLOSED,       /* Not an error, gracefully closed by peer */

/* Protocol errors */
    AFT_PERR_TYPE,           /* Unexpected wrong block type received */
    AFT_PERR_STAT,           /* Unexpected wrong status received */

/* Implementation errors */
    AFT_IERR_BSIZE,          /* Buffer size too small */

/* Normal errors */
    AFT_ERR_ANON,            /* Anonymous user not allowed */
    AFT_ERR_LOGIN,           /* Incorrect login */
    AFT_ERR_NODIR,           /* Directory does not exist */
    AFT_ERR_NOFILE,          /* File does not exist */
    AFT_ERR_ACCESS,          /* Permission denied */
    AFT_ERR_SRVSYS           /* System error in server */
};

/* Exports */
int aft_init();
void aft_cleanup();
int aft_get_last_error();
const char *aft_get_last_error_str();
int aft_get_last_sys_error();
const char* aft_get_last_sys_error_str();
int aft_close(int fd);
int aft_send_block(int fd, type_t type, const char *data, dsize_t size);
int aft_send_data(int fd, const char *data, dsize_t size);
int aft_send_cdata(int fd, const char *data, dsize_t size);
int aft_recv_block(int fd, block_t *block);
/* Client functions */
int aft_resolve(const char *host, struct addrinfo **addrs);
int aft_get_sa_addr_str(const struct sockaddr *addr, char *str, size_t strlen);
int aft_get_ai_addr_str(const struct addrinfo *addr, char *str, size_t strlen, int flags);
int aft_open(const struct addrinfo *addr, uint16_t port);
int aft_open_host(const char *host, uint16_t port);
int aft_ping(int fd, struct timespec *rtt);
int aft_pwd(int fd, char *pwd, int len);
int aft_cd(int fd, const char *dir);
int aft_ls(int fd, dir_t *dir, size_t dirlen);
int aft_login(int fd, const char *user, const char *passwd);
/* Server functions */
int aft_listen(struct addrinfo *addr, uint16_t port);
int aft_accept(int fd, struct sockaddr *sa, socklen_t *len);
void aft_parse_cmd(const uint8_t *data, dsize_t bsize, command_t *command);
int aft_check_cmd(const command_t *command);
int aft_recv_cmd(int fd, command_t *command);
int aft_send_stat(int fd, stat_t stat, const char *data, dsize_t size);

#ifdef __cplusplus
}
#endif

#endif /* _ARFTRANSFER_H */
