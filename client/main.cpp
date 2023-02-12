#include <iostream>
#include <cxxopts.hpp>

#include <libarftransfer/arftransfer.h>

constexpr uint16_t defaultPort = 8088;

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
    uint16_t iport = defaultPort;
    if (result.count("port"))
        iport = result["port"].as<int>();

    if (result.count("host")) {
        if (aft_open(result["host"].as<std::string>().c_str(), iport) != AFT_OK) {
            std::cout << "Error: " << aft_get_last_error_str() << ": " << aft_get_last_sys_error_str() << std::endl;
            return 1;
        }
    }

    std::cout << "success" << std::endl;
}