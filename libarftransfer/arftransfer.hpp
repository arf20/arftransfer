#pragma once

#include <cstdint>
#include <sys/types.h>

#define VER 0x12

enum client_btype_t : uint8_t {
    TYPE_CLIENT_PING,
    TYPE_CLIENT_CMD,
    TYPE_CLIENT_DATA,
    TYPE_CLIENT_CDATA
};

enum server_btype_t : uint8_t {
    TYPE_SERVER_PING,
    TYPE_SERVER_STAT,
    TYPE_SERVER_DATA,
    TYPE_SERVER_CDATA
};

enum cmd_t : uint8_t {
    CMD_NC,
    CMD_LOGIN,
    CMD_LS,
    CMD_CD,
    CMD_GET,
    CMD_PUT,
    CMD_ENCRYPT
};

enum stat_t : uint8_t {
    STAT_NS,
    STAT_LOGGEDIN,
    STAT_LSD,
    STAT_ACK,
    STAT_ELOGIN,
    STAT_ENODIR,
    STAT_ENOFILE,
    STAT_EACCESS,
    STAT_ESYS
};

struct block_header_t {
    uint8_t type;
    uint8_t version;
    uint16_t size;
};

struct command_header_t {
    cmd_t cmd;
    uint16_t size;
    uint8_t zero;   // reserved
};

struct status_header_t {
    stat_t stat;
    uint16_t size;
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
