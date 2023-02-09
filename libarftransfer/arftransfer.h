#ifndef _ARFTRANSFER_H
#define _ARFTRANSFER_H

#include <stdint.h>
#include <sys/types.h>

#define VER 0x12

// Block types
//   Client
#define TYPE_CLIENT_PING    0x00
#define TYPE_CLIENT_CMD     0x01
#define TYPE_CLIENT_DATA    0x02
#define TYPE_CLIENT_CDAT    0x03
//   Server
#define TYPE_SERVER_PING    0x00
#define TYPE_SERVER_STAT    0x01
#define TYPE_SERVER_DATA    0x02
#define TYPE_SERVER_CDAT    0x03

// Command types
#define CMD_NC              0x00
#define CMD_LOGIN           0x01
#define CMD_LS              0x02
#define CMD_CD              0x03
#define CMD_GET             0x04
#define CMD_PUT             0x05
#define CMD_ENCRYP          0x06
// Status types
#define STAT_NS             0x00
#define STAT_LOGGEDIN       0x01
#define STAT_LSD            0x02
#define STAT_ACK            0x03
#define STAT_ELOGIN         0x04
#define STAT_ENODIR         0x05
#define STAT_ENOFILE        0x06
#define STAT_EACCESS        0x07
#define STAT_ESY            0x08

// Types
typedef uint8_t type_t;
typedef uint8_t ver_t;
typedef uint8_t dsize_t;
typedef uint8_t cmd_t;
typedef uint8_t stat_t;

// Headers
struct block_header_t {
    type_t type;
    ver_t version;
    dsize_t size;
};

struct command_header_t {
    cmd_t cmd;
    dsize_t size;
    uint8_t zero;   // reserved
};

struct status_header_t {
    stat_t stat;
    dsize_t size;
    uint8_t zero;   // reserved
};

struct dir_entry_t {
    mode_t mode;    // uint32_t
    uid_t uid;      // uint32_t
    gid_t gid;      // uint32_t
    size_t size;    // uint64_t
    time_t mtime;   // uint64_t
    char name[256]; // last char is NUL
};

#endif /* _ARFTRANSFER_H */
