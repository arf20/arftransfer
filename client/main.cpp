#include <iostream>
#include <iomanip>

#include <sys/stat.h>
#include <unistd.h>

#include <cxxopts.hpp>

#include <libarftransfer/arftransfer.h>

#define AFT_CHECK(x) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str(); if (aft_get_last_error() >= AFT_SYSERR_SOCKET && aft_get_last_error() <= AFT_SYSERR_ACCEPT) { std::cout << ": " << aft_get_last_sys_error_str(); } std::cout << std::endl; }
#define AFT_CHECK_A(x, a) if ((x) != AFT_OK) { std::cout << "Error: " << aft_get_last_error_str(); if (aft_get_last_error() >= AFT_SYSERR_SOCKET && aft_get_last_error() <= AFT_SYSERR_ACCEPT) { std::cout << ": " << aft_get_last_sys_error_str(); } std::cout << std::endl; a; }

#define CHECKFD if (fd == -1) { std::cout << "Not connected" << std::endl; continue; }

int connect(const std::string& host, uint16_t port) {
    struct addrinfo *addr = NULL, *p = NULL;
    char addrstr[256];
    AFT_CHECK(aft_resolve(host.c_str(), &addr))
    p = addr;
    int fd = -1;

    while (p) {
        AFT_CHECK(aft_get_ai_addr_str(p, addrstr, 256, 1))
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
        ("host", "The host to open", cxxopts::value<std::string>());

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
        std::cout << "Connection established" << std::endl;
    }

    bool stopcli = false;
    std::string command;
    std::string arg;

    while (!stopcli) {
        std::cout << "arftransfer> ";
        std::cin >> command;

        if (command == "help" || command == "h") {
            std::cout << "\thelp\t\t\tDisplay this message"
                << "\n\texit|e\t\t\tExit lol"
                << "\n\topen|o [host] [port]\tOpen connection"
                << "\n\tping|p\t\t\tMeasure RTT"
                << "\n\tpwd\t\t\tGet current working directory"
                << "\n\tcd <path>\t\tChange directory to path"
                << "\n\tls\t\t\tGet directory listing"
                << "\n\tlogin [user]\t\tLogin into system"
                << "\n\tclose|c\t\t\tClose connection" << std::endl;
        }
        else if (command == "exit" || command == "e") {
            return 0;
        }
        else if (command == "open" || command == "o") {
            std::cout << "Host> ";
            std::string host;
            std::cin >> host;
            std::cout << "Port [" << iport << "]> ";
            uint16_t port = iport;
            std::cin >> port;

            if ((fd = connect(host, port)) < 0) {
                return 1;
            }

            std::cout << "Connection established" << std::endl;
        }
        else if (command == "ping" || command == "p") {
            CHECKFD
            timespec rtt;
            AFT_CHECK_A(aft_ping(fd, &rtt), continue)
            double millis = 1000.0 * (rtt.tv_sec + (rtt.tv_nsec / 1000000000.0));
            std::cout << "Answer RTT: " << millis << "ms" << std::endl;
        }
        else if (command == "pwd") {
            CHECKFD
            char pwd[256];
            AFT_CHECK_A(aft_pwd(fd, pwd, 256), continue)
            std::cout << pwd << std::endl;
        }
        else if (command == "cd") {
            CHECKFD
            std::cin >> arg;
            AFT_CHECK_A(aft_cd(fd, arg.c_str()), continue)
        }
        else if (command == "ls") {
            CHECKFD
            dir_t dir;
            dir_entry_t dirdata[256];
            dir.entries = dirdata;
            AFT_CHECK_A(aft_ls(fd, &dir, sizeof(dir_entry_t) * 256), continue);

            for (int i = 0; i < dir.count; i++) {
                std::tm* tm = std::localtime(&dirdata[i].mtime);

                std::cout << (S_ISDIR(dirdata[i].mode) ? "d" : "-")
                << ((dirdata[i].mode & S_IRUSR) ? "r" : "-")
                << ((dirdata[i].mode & S_IWUSR) ? "w" : "-")
                << ((dirdata[i].mode & S_IXUSR) ? "x" : "-")
                << ((dirdata[i].mode & S_IRGRP) ? "r" : "-")
                << ((dirdata[i].mode & S_IWGRP) ? "w" : "-")
                << ((dirdata[i].mode & S_IXGRP) ? "x" : "-")
                << ((dirdata[i].mode & S_IROTH) ? "r" : "-")
                << ((dirdata[i].mode & S_IWOTH) ? "w" : "-")
                << ((dirdata[i].mode & S_IXOTH) ? "x" : "-")
                << "\t" << dirdata[i].uid << "\t" << dirdata[i].gid
                << "\t" << dirdata[i].size
                << "\t" << std::put_time(tm, "%b %d %Y %H:%M")
                << "\t" << dirdata[i].name << std::endl;
            }
        }
        else if (command == "login") {
            CHECKFD
            std::string user;
            std::string passwd;
            std::cin >> user;
            passwd = getpass("Password: ");
            AFT_CHECK_A(aft_login(fd, user.c_str(), passwd.c_str()), continue)
        }
        else if (command == "close" || command == "c") {
            CHECKFD
            aft_close(fd);
            fd = -1;
        } 
        else {
            std::cout << "Invalid command" << std::endl;
        }

        command.clear();
    }
    
}
