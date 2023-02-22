# arftransfer
Simple, fast and secure file transfer program.
Using the AFT protocol. See PROTOCOL.md

## Build
Install dependencies: zlib1g-dev libcxxopts-dev libpam0g-dev
Like any other cmake project
```
mkdir build && cd build
cmake ..
make
```

## Client options
```
Usage:
    arftransfer [-hv] [-p port] [-P passwd] [host]
```
```
    help                    Display this message
    exit|e                  Exit lol
    open|o [host] [port]    Open connection
    ping|p                  Measure RTT
    pwd                     Get current working directory
    cd <path>               Change directory to path
    ls                      Get directory listing
    login [user]            Login into system, prompts for password
    close|c                 Close connection
```

## Server details
Config file
```
# Sample config file
port=8088
address=0.0.0.0

allowanon=true
anonroot=/srv
anonwriteenable=true
```
If `allowanon` key is not present, anonymous login is presumed disabled

