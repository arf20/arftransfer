#include <iostream>
#include <cxxopts.hpp>

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl; }
#define AFT_CHECK_A(x, a) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl; a; }

#define CHECKFD if (fd == -1) { std::cout << "Not connected" << std::endl; continue; }

int connect(const std::string& host, uint16_t port) {
    struct addrinfo *addr = NULL, *p = NULL;
    char addrstr[256];
    AFT_CHECK(aft_resolve(host.c_str(), &addr))
    p = addr;
    int fd = 0;

    while (p) {
        AFT_CHECK(aft_get_addr_str(p, addrstr, 256, 1))
        std::cout << "Trying " << addrstr << "..." << std::endl;

        if ((fd = aft_open(p, port)) < 0) {
            std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
        }
        else return fd;

        p = p->ai_next;
    }

    return -1;
}

int main(int argc, char **argv) {
    cxxopts::Options options("arftransfer", "arftransfer: Simple, fast and secure file transfer program - arf20");

    options.add_options()
        ("h,help", "Display this message", cxxopts::value<bool>())
        ("v,verbose", "Verbose output", cxxopts::value<bool>())
        ("p,port", "Specify port", cxxopts::value<std::string>())
        ("u,user", "Username", cxxopts::value<std::string>())
        ("P,passwd", "Password", cxxopts::value<std::string>())
        ("host", "The host to open", cxxopts::value<std::string>())
        ;

    options.parse_positional({"host"});
    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    // Main
    if (aft_init() != AFT_OK) {
        return 1;
    }

    // Handle options
    uint16_t iport = 8088; // default port
    if (result.count("port"))
        iport = std::stoi(result["port"].as<std::string>());

    int fd = -1;
    if (result.count("host")) {
        if ((fd = connect(result["host"].as<std::string>(), iport)) < 0) {
            return 1;
        }
    }

    std::cout << "Connection established" << std::endl;

    bool stopcli = false;
    std::string command;
    while (!stopcli) {
        std::cout << "arftransfer> ";
        std::cin >> command;

        if (command == "open") {
            std::cout << "Host> ";
            std::string host;
            std::cin >> host;
            std::cout << "Port [" << iport << "] >";
            uint16_t port = iport;
            std::cin >> port;

            if ((fd = connect(host, port)) < 0) {
                return 1;
            }
        }
        else if (command == "ping") {
            CHECKFD
            timespec rtt;
            AFT_CHECK_A(aft_ping(fd, &rtt), continue)
            double millis = (rtt.tv_sec * 1000.0) + (rtt.tv_nsec / 1000.0);
            std::cout << "Answer RTT: " << millis << "ms" << std::endl;
        }
        else if (command == "close") {
            CHECKFD
            aft_close(fd);
            fd = -1;
        }

        command.clear();
    }
    
}