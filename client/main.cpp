#include <iostream>
#include <cxxopts.hpp>

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl; exit(1); }

int connect(const std::string& host, uint16_t port) {
    uint32_t addr;
    char addrstr[256];
    AFT_CHECK(aft_resolve(host.c_str(), &addr))
    AFT_CHECK(aft_get_addr_str(addr, addrstr, 256))
    std::cout << "Trying " << addrstr << "..." << std::endl;

    int fd = 0;
    if ((fd = aft_open(addr, port)) < 0) {
        std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
        exit(1);
    }

    return fd;
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
            std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
            return 1;
        }
    }

    
}