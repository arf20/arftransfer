# AFT Protocol - Version 1.0
A file transfer protocol over TCP/IP. One single connection client -> server, optionally supports gzip compression and TLS encryption.
## 1. Block Header Definition

```
<--------- 4 bytes --------->
#############################
# TYPE # VER  # SIZE        #
#############################
# DATA                      #
# ...                       #
#############################
```
```cpp
struct block_header_t {
    uint8_t type;
    uint8_t version;
    uint16_t size;
};
```
Current protocol version is 1.0 (0x10)

## 2. Block Types

### 2.1. From client
#### 2.1.1. 0x00 PING
No data. Size = 0
#### 2.1.2. 0x01 COMMAND
In which case data:
```
<--------- 4 bytes --------->
+---------------------------+
# CMD  #  0 (ARGS RESV)     |
+---------------------------+
# [TEXT ARG] OR NULL        |
+---------------------------+
```
#### 2.1.3. 0x02 DATA (client -> server)
Directly raw file data. Could be a whole file smaller than block size, or one of the blocks of the file. Block size is defined in the client and the server independently.
### 2.2. From server
#### 2.2.1. 0x00 PING ANSWER
No data. Size = 0.
#### 2.2.2. 0x01 STATUS
```
<--------- 4 bytes --------->
+---------------------------+
| STAT # [SIZE]      | 0    |
+---------------------------+
| [DATA]                    |
+---------------------------+
```
```c
struct status_header_t {
    uint8_t stat;
    uint16_t size;
};
```
#### 2.2.3. 0x02 DATA (server -> client)
Same as 2.1.3.

## 3. Commands
From client
### 3.1. 0x00 NC - Null Command
No arguments.
No action performed.
Returns: 0x00 NS
### 3.2. 0x01 LS - Directory Listing
No arguments.
Returns: 0x01 LSD or 0x05 EACCESS on error
### 3.3. 0x02 CD - Change Directory
Text argument: The name or path of a directory
Returns: 0x02 ACK on success, or 0x03 ENODIR, 0x05 EACCESS or 0x06 ESYS on error
### 3.4. 0x03 GET - Get File
Text argument: The name or path of file to get
Returns: 0x02 ACK on success, or 0x04 NOFILE, 0x05 EACCESS or 0x06 ESYS on error
The client should now receive 0x02 DATA blocks from server
### 3.4. 0x04 PUT - Put File
Text argument: The name or path of file to put
Returns: 0x02 ACK on success, or 0x05 EACCESS or 0x06 ESYS on error
The client should now transmit 0x02 DATA blocks to server

## 4. Status
From server
### 4.1. 0x00 NS - Null Status
No data.
### 4.2. 0x01 LSD - List Directory Data
Result of successful 0x01 LS command, where dir is specified.
Data contains a number of entries, each as:
```
<--------- 4 bytes --------->
+---------------------------+
| MODE                      |
+---------------------------+
| UID                       +
+---------------------------+
| GID                       |
+---------------------------+
| SIZE                      |
|                           |
+---------------------------+
| MOD TIME                  |
|                           |
+---------------------------+
| NAME                      |
  ....
|                           |
+---------------------------+
```
```c
struct dir_entry_t {
    mode_t mode;    // uint32_t
    uid_t uid;      // uint32_t
    gid_t gid;      // uint32_t
    size_t size;    // uint64_t
    time_t mtime;   // uint64_t
    char name[256]; // last char is NUL
}
```
Each entry is henceforth 324 bytes

### 4.3. 0x02 ACK - Command Acknowledge
No data. Result of succesful command.
### 4.4. 0x03 ENODIR - Directory does not exist
No data.
### 4.5. 0x04 ENOFILE - File does not exist
No data.
### 4.6. 0x05 EACCESS - Permission denied
No data.
### 4.7. 0x06 ESYS - Generic system error in the server
No data.
