#include <iostream>
#include <cxxopts.hpp>

int main() {
    cxxopts::Options options("arftransfer", "Simple, fast and secure file transfer program");

    options.add_options()
        ("v,verbose", "Verbose output", cxxopts::value<bool>()->default_value("false"))
        ("u,user", "Username", cxxopts::value<bool>()->default_value("false"))
        ("p,pass", "Password", cxxopts::value<bool>()->default_value("false"))
        ("host", "The host to open", cxxopts::value<std::string>())
        ;
}