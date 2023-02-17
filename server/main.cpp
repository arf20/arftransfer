#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>

#include "inireader.hpp"

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl; }

const std::string conffname = "server.conf";

std::vector<std::thread> acceptThreads;
std::vector<std::thread> connectionThreads;

// receive loop
void receiveLoop(int fd) {

}

// accept loop
void acceptLoop(int afd) {
    int cfd = -1;
    sockaddr sa;
    socklen_t len;
    char addrstr[256];
    while (true) {
        if ((cfd = aft_accept(afd, &sa, &len)) < 0) {
            std::cout << "Error accepting: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
            return;
        }
        
        AFT_CHECK(aft_get_sa_addr_str(&sa, addrstr, 256))
        std::cout << "Connection accepted: " << addrstr << ":" << std::endl;

        connectionThreads.push_back(std::thread(receiveLoop, cfd));
    }
}

void createConfig(const std::string& path) {
    std::ofstream conffile("server.conf");
    if (!conffile.is_open()) {
        std::cout << "Error writing config file" << std::endl;
        exit(1);
    }
    conffile << "# Sample config file\nport=8088\naddress=0.0.0.0,::\n";
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