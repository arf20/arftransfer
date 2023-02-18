#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <chrono>

#include "inireader.hpp"

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl; }

struct client {
    int fd;
    std::string addr;
};

const std::string conffname = "server.conf";

std::vector<std::thread> acceptThreads;
std::vector<client> clients;

// receive loop
void receiveLoop(client c) {
    block_t block;
    while (true) {
        int r = aft_recv_block(c.fd, &block);
        if (r == AFT_ERROR) {
            std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
            return;
        } else if (r == 0) {
            std::cout << "Connection from " << c.addr << " closed" << std::endl;
            aft_close(c.fd);
            return;
        }

        std::cout << "Block received from " << c.addr << ": ";

        switch (block.header.type) {
            case AFT_TYPE_PING: {
                std::cout << "PING" << std::endl;
                aft_send_block(c.fd, AFT_TYPE_PING, NULL, 0);
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
        std::thread t(receiveLoop, c);
        t.detach();

        clients.push_back(c);
    }
}

void createConfig(const std::string& path) {
    std::ofstream conffile("server.conf");
    if (!conffile.is_open()) {
        std::cout << "Error writing config file" << std::endl;
        exit(1);
    }
    conffile << "# Sample config file\nport=8088\naddress=0.0.0.0\n";
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

    std::cout << "end";
}