#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <list>
#include <thread>
#include <chrono>
#include <filesystem>

#include "inireader.hpp"

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str(); if (aft_get_last_error() >= AFT_SYSERR_SOCKET && aft_get_last_error() <= AFT_SYSERR_ACCEPT) { std::cout << ": " << aft_get_last_sys_error_str(); } std::cout << std::endl; }
#define AFT_CHECK_A(x, a) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str(); if (aft_get_last_error() >= AFT_SYSERR_SOCKET && aft_get_last_error() <= AFT_SYSERR_ACCEPT) { std::cout << ": " << aft_get_last_sys_error_str(); } std::cout << std::endl; a; }

struct client {
    int fd;
    std::string addr;
    std::string pwd;
};

const std::string conffname = "server.conf";

std::list<std::thread> acceptThreads;
std::list<client> clients;

std::vector<std::string> directories;

bool handleCommand(client& c, const command_t& cmd) {
    char args[256];
    switch (cmd.header.cmd) {
        case AFT_CMD_NC: break;
        case AFT_CMD_PWD: {
            std::cout << "PWD" << std::endl;
            AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_PWDD, c.pwd.c_str(), c.pwd.length()), return false)
        } break;
        case AFT_CMD_CD: {
            std::copy(cmd.targ, cmd.targ + cmd.header.size, args);
            args[cmd.header.size] = '\0';
            std::cout << "CD " << args << ": ";

            std::string npwd;
            if (args[0] == '/') npwd = std::string(args);
            else if (c.pwd == "/") npwd = "/" + std::string(args);
            else npwd = c.pwd + "/" + std::string(args);

            if (!(std::filesystem::exists(npwd) && std::filesystem::is_directory(npwd))) {
                std::cout << npwd << " ENODIR" << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ENODIR, NULL, 0), return false)
            }
            else {
                c.pwd = npwd;
                std::cout << npwd << " ACK" << std::endl;
                AFT_CHECK_A(aft_send_stat(c.fd, AFT_STAT_ACK, NULL, 0), return false)
            }
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

        std::cout << "Block received from " << c.addr << ": ";

        switch (block.header.type) {
            case AFT_TYPE_PING: {
                std::cout << "PING" << std::endl;
                aft_send_block(c.fd, AFT_TYPE_PING, NULL, 0);
            } break;
            case AFT_TYPE_CMD: {
                std::cout << "CMD: ";
                aft_parse_cmd(block.data, block.header.size, &cmd);
                AFT_CHECK(aft_check_cmd(&cmd))
                if (!handleCommand(c, cmd)) {
                    aft_close(c.fd);
                    clients.erase(cit);
                    return;
                }
            } break;
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
    conffile << "# Sample config file\nport=8088\naddress=0.0.0.0\nroot=/srv";
    conffile.close();

}

int main() {
    std::cout << "Starting arftransfer server" << std::endl;

    INIReader reader("server.conf");

    if (reader.ParseError() != 0) {
        std::cout << "Config file not found, creating one..." << std::endl;
        createConfig(".");
        return 1;
    }

    uint16_t port = reader.GetInteger("", "port", 0);

    std::stringstream addressesss(reader.Get("", "address", ""));
    std::vector<std::string> addresses;
    std::string addrstr;
    while (std::getline(addressesss, addrstr, ','))
        addresses.push_back(addrstr);

    // arftransfer init
    aft_init();

    // Create listen sockets
    for (const std::string& addr : addresses) {
        struct addrinfo *ai = NULL, *p = NULL;
        char addrstr[256];
        AFT_CHECK(aft_resolve(addr.c_str(), &ai))
        p = ai;
        int fd = -1;

        while (p) {
            AFT_CHECK(aft_get_ai_addr_str(p, addrstr, 256, 1))

            std::cout << "Listening on " << addrstr << " port " << port << std::endl;
            if ((fd = aft_listen(p, port)) < 0) {
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