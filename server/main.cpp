#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

#include "inireader.hpp"

#include <libarftransfer/arftransfer.h>

const std::string conffname = "server.conf";

std::vector<int> listenSockets;

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
    std::cout << "Listen port: " << port << std::endl;

    std::cout << "Listen addresses: ";
    std::stringstream addressesss(reader.Get("", "address", ""));
    std::vector<std::string> addresses;
    std::string addrstr;
    while (std::getline(addressesss, addrstr, ',')) {
        addresses.push_back(addrstr);
        std::cout << addrstr << ", ";
    }
    std::cout << std::endl;

    // Create listen sockets
    for (const std::string& addr : addresses) {

    }
}