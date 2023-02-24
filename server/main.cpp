#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <list>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>

#include <security/pam_appl.h>
#include <pwd.h>

#include "inireader.hpp"

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str(); if (aft_get_last_error() >= AFT_SYSERR_SOCKET && aft_get_last_error() <= AFT_SYSERR_ACCEPT) { std::cout << ": " << aft_get_last_sys_error_str(); } std::cout << std::endl; }
#define AFT_CHECK_A(x, a) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str(); if (aft_get_last_error() >= AFT_SYSERR_SOCKET && aft_get_last_error() <= AFT_SYSERR_ACCEPT) { std::cout << ": " << aft_get_last_sys_error_str(); } std::cout << std::endl; a; }

#define CHECK_LOGGED if (!c.logged && !config::anonAllowed) { \
    std::cout << "EANON" << std::endl; \
    AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_EANON, NULL, 0), return false) \
    break; \
}

const std::string conffname = "server.conf";

struct client {
    int fd;
    std::string addr;
    std::string pwd;
    bool logged;
    std::string user;
    uid_t uid;
    gid_t gid;
};

std::list<std::thread> acceptThreads;
std::list<client> clients;

namespace config {
    uint16_t port;
    std::vector<std::string> addresses;
    bool anonAllowed = false;
    std::string anonRoot;
};

char *readbuffer = new char[AFT_MAX_BLOCK_DATA_SIZE];
char *writebuffer = new char[AFT_MAX_BLOCK_DATA_SIZE];

// function used to get user input for pam (hack)
int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    *resp = (struct pam_response*)appdata_ptr;
    return PAM_SUCCESS;
}

bool handleCommand(client& c, const command_t& cmd) {
    char args[AFT_MAX_CMD_DATA_SIZE];
    switch (cmd.header.cmd) {
        case AFT_CMD_NC: break;
        case AFT_CMD_PWD: {
            std::cout << "PWD: ";
            CHECK_LOGGED
            std::cout << "PWDD ";
            if (!c.logged) { std::cout << "[" << config::anonRoot << "]"; }
            std::cout << c.pwd << " ACK" << std::endl;
            AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_PWDD, c.pwd.c_str(), c.pwd.length()), return false)
        } break;
        case AFT_CMD_CD: {
            std::copy(cmd.targ, cmd.targ + cmd.header.size, args);
            args[cmd.header.size] = '\0';
            std::cout << "CD " << args << ": ";
            CHECK_LOGGED

            std::string npwd;
            if (args[0] == '/') npwd = std::string(args);
            else if (c.pwd == "/") npwd = "/" + std::string(args);
            else npwd = c.pwd + "/" + std::string(args);

            npwd = std::filesystem::weakly_canonical(std::filesystem::path(npwd));

            std::string realpwd = !c.logged ? config::anonRoot + npwd : npwd;

            if (!(std::filesystem::exists(realpwd) && std::filesystem::is_directory(realpwd))) {
                if (!c.logged) { std::cout << "[" << config::anonRoot << "]"; }
                std::cout << npwd << " ENODIR" << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ENODIR, NULL, 0), return false)
                break;
            }
            
            c.pwd = npwd;

            if (!c.logged) { std::cout << "[" << config::anonRoot << "]"; }
            std::cout << c.pwd << " ACK" << std::endl;
            AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ACK, NULL, 0), return false)
        } break;
        case AFT_CMD_LS: {
            std::cout << "LS: ";
            CHECK_LOGGED
            // isolate anon user
            std::string realpwd = !c.logged ? config::anonRoot + c.pwd : c.pwd;
            
            if (!std::filesystem::exists(realpwd)) {
                std::cout << "ESYS Path " << realpwd << " does not exist" << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ESYS, NULL, 0), return false)
                break;
            }

            int i = 0;
            for (const auto& file : std::filesystem::directory_iterator(realpwd))
                i++;

            dir_entry_t *dir = new dir_entry_t[i];
            struct stat sb;

            i = 0;
            for (const auto& file : std::filesystem::directory_iterator(realpwd)) {
                std::string fname = file.path().filename().generic_string();
                lstat(file.path().c_str(), &sb);

                dir[i].mode = sb.st_mode;
                dir[i].uid = sb.st_uid;
                dir[i].gid = sb.st_gid;
                dir[i].size = sb.st_size;
                dir[i].mtime = sb.st_mtim.tv_sec;
                
                std::copy(fname.c_str(), fname.c_str() + fname.length(), dir[i].name);
                dir[i].name[fname.length()] = '\0';

                i++;
            }

            std::cout << "LSD ";
            if (!c.logged) { std::cout << "[" << config::anonRoot << "]"; }
            std::cout << c.pwd << " " << i << " entries" << std::endl;
            AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_LSD, (char*)dir, sizeof(dir_entry_t) * i), return false)

            delete[] dir;
        } break;
        case AFT_CMD_LOGIN: {
            char *user = (char*)cmd.targ;
            char *passwd = new char[strlen(user) + 1];
            strcpy(passwd, (char*)(cmd.targ + strlen(user) + 1));
            std::cout << "LOGIN " << user << ": ";

            struct pam_response *reply = new struct pam_response;
            reply->resp = passwd;
            reply->resp_retcode = 0;

            struct pam_conv pamc = { function_conversation, reply };
            pam_handle_t *pamh = NULL; 

            int r = PAM_ABORT;
            if ((r = pam_start("login", user, &pamc, &pamh)) != PAM_SUCCESS) {
                std::cout << "Error: pam_start: " << pam_strerror(pamh, r) << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ELOGIN, NULL, 0), return true)
                break;
            }

            if ((r = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
                std::cout << "ELOGIN" << std::endl;
                std::cout << "Error: pam_authenticate: " << pam_strerror(pamh, r) << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ELOGIN, NULL, 0), return false)
                break;
            }

            pam_end(pamh, 0);

            c.logged = true;
            c.user = std::string(user);

            struct passwd *pw = getpwnam(user);
            c.pwd = pw->pw_dir;
            c.uid = pw->pw_uid;
            c.gid = pw->pw_gid;

            std::cout << "ACK" << std::endl;
            AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ACK, NULL, 0), return false)

            
        } break;
        case AFT_CMD_GET: {
            char *path = (char*)cmd.targ;
            std::string realpwd = !c.logged ? config::anonRoot + c.pwd : c.pwd + "/";

            std::cout << "GET ";
            if (!c.logged) std::cout << "[" << config::anonRoot << "]";
            std::cout << "[" << c.pwd << (c.logged ? "/" : "") << "]" << path << ": ";
            
            if (!std::filesystem::exists(realpwd + path)) {
                std::cout << "ENOFILE" << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ENOFILE, NULL, 0), return false)
                break;
            }

            std::ifstream file(realpwd + path, std::ios::binary);
            if (!file) {
                if (errno == EACCES) {
                    std::cout << "EACCESS" << std::endl;
                    AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_EACCESS, NULL, 0), return false)
                    break;
                } else {
                    std::cout << "ESYS" << std::endl;
                    AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ESYS, NULL, 0), return false)
                    break;
                }
            }

            auto begin = file.tellg();
            file.seekg(0, std::ios::end);
            auto end = file.tellg();
            file.seekg(0, std::ios::beg);
            auto fsize = end - begin;
            size_t sendSize = 1;

            while (sendSize) {
                if (fsize < AFT_MAX_BLOCK_DATA_SIZE) { sendSize = fsize; fsize -= sendSize; }
                else { sendSize = AFT_MAX_BLOCK_DATA_SIZE; fsize -= sendSize; }

                file.read(readbuffer, sendSize);
                AFT_CHECK_A(aft_send_data(c.fd, readbuffer, sendSize), return false)
                std::cout << sendSize << " ";
            }

            // terminate transfer with a data block of size 0
            AFT_CHECK_A(aft_send_data(c.fd, NULL, 0), return false)

            std::cout << ";" << std::endl;
            
        } break;
    }

    return true;
}

// receive loop
void receiveLoop(std::list<client>::iterator cit) {
    client& c = *cit;
    block_t block;
    command_t cmd;

    while (true) {
        if (aft_recv_block(c.fd, &block) != AFT_OK) {
            if (aft_get_last_error() != AFT_SYSERR_CLOSED)
                std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
            else
                std::cout << "Connection from " << c.addr << " closed" << std::endl;
            aft_close(c.fd);
            clients.erase(cit);
            return;
        }

        std::cout << "Block received from " << c.addr << " (" << (!c.logged ? "anon" : c.user) << "): ";

        switch (block.header.type) {
            case AFT_TYPE_PING: {
                std::cout << "PING" << std::endl;
                aft_send_block(c.fd, AFT_TYPE_PING, NULL, 0);
            } break;
            case AFT_TYPE_CMD: {
                std::cout << "CMD: ";
                AFT_CHECK(aft_parse_cmd(block.data, block.header.size, &cmd))
                if (!handleCommand(c, cmd)) {
                    aft_close(c.fd);
                    clients.erase(cit);
                    return;
                }
            } break;
            default: {
                std::cout << "Unexpected block type" << std::endl;
            }
        }
    }
}

// accept loop
void acceptLoop(int afd) {
    int cfd = -1;
    sockaddr sa;
    socklen_t len = sizeof(sockaddr);
    char addrstr[256];
    while (true) {
        len = sizeof(sockaddr);
        if ((cfd = aft_accept(afd, &sa, &len)) < 0) {
            std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
            return;
        }
        
        AFT_CHECK(aft_get_sa_addr_str(&sa, addrstr, 256))
        std::cout << "Connection accepted: " << addrstr << std::endl;

        client c;
        c.fd = cfd;
        c.addr = std::string(addrstr);
        c.pwd = "/";
        c.logged = false;

        clients.push_back(c);

        std::thread t(receiveLoop, --clients.end());
        t.detach();
    }
}

void createConfig(const std::string& path) {
    std::ofstream conffile("server.conf");
    if (!conffile.is_open()) {
        std::cout << "Error writing config file" << std::endl;
        exit(1);
    }
    conffile << "# Sample config file\nport=8088\naddress=0.0.0.0\nallowanon=true\nanonroot=/srv";
    conffile.close();

}

int main() {
    std::cout << "Starting arftransfer server" << std::endl;

    // Parse config
    INIReader reader("server.conf");

    if (reader.ParseError() != 0) {
        std::cout << "Config file not found, creating one..." << std::endl;
        createConfig(".");
        return 1;
    }

    config::port = reader.GetInteger("", "port", 8088);

    std::stringstream addressesss(reader.Get("", "address", "0.0.0.0"));
    std::string addrstr;
    while (std::getline(addressesss, addrstr, ','))
        config::addresses.push_back(addrstr);

    if (reader.GetBoolean("", "allowanon", false)) {
        config::anonAllowed = true;
        config::anonRoot = reader.Get("", "anonroot", "/srv");
        if (config::anonRoot.back() != '/') config::anonRoot += "/";
        config::anonRoot.pop_back();
    }

    std::cout << "Port: " << config::port << std::endl
        << "Address: "; for (auto a : config::addresses) std::cout << a << ", ";
    std::cout << std::endl << "Anonymous enabled: " << (config::anonAllowed ? "true" : "false") << std::endl;
    if (config::anonAllowed) std::cout << "Anonymous root: " << config::anonRoot << std::endl;

    // arftransfer init
    aft_init();

    // Create listen sockets
    for (const std::string& addr : config::addresses) {
        struct addrinfo *ai = NULL, *p = NULL;
        char addrstr[256];
        AFT_CHECK(aft_resolve(addr.c_str(), &ai))
        p = ai;
        int fd = -1;

        while (p) {
            AFT_CHECK(aft_get_ai_addr_str(p, addrstr, 256, 1))

            std::cout << "Listening on " << addrstr << " port " << config::port << std::endl;
            if ((fd = aft_listen(p, config::port)) < 0) {
                std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
                p = p->ai_next;
                continue;
            }

            acceptThreads.push_back(std::thread(acceptLoop, fd));

            p = p->ai_next;
        }
    }

    for (std::thread& t : acceptThreads)
        t.join();
}