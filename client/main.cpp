#include <iostream>
#include <cxxopts.hpp>

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl; exit(1); }

int connect(const std::string& host, uint16_t port) {
    struct addrinfo *addr, *p;
    char addrstr[256];
    AFT_CHECK(aft_resolve(host.c_str(), &addr))
    p = addr;
    int fd = 0;

    while (p) {
        AFT_CHECK(aft_get_addr_str(p, addrstr, 256))
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

    int fd = 0;
    if (result.count("host")) {
        if ((fd = connect(result["host"].as<std::string>(), iport)) < 0) {
            return 1;
        }
    } else {
        std::cout << "Host> ";
        std::string host;
        std::cin >> host;
        std::cout << "Port> ";
        uint16_t port;
        std::cin >> port;

        if ((fd = connect(host, port)) < 0) {
            return 1;
        }
    }


    
}