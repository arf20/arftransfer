# AFT Protocol Specification - Version 1.2
A file transfer protocol over TCP/IP. One single connection client -> server, optionally supports gzip compression and TLS encryption.

## 1. Block Header Definition

```
<--------- 4 bytes --------->
+------+------+-------------+
| TYPE | VER  | SIZE        |
+------+------+-------------+
| DATA                      |
| ...                       |
+---------------------------+
```
```cpp
struct block_header_t {
    uint8_t type;
    uint8_t version;
    uint16_t size;
};
```
Current protocol version is 1.2 (0x12).

## 2. Block Types
### 2.1. From client
#### 2.1.1. 0x00 PING
No data. Size = 0
#### 2.1.2. 0x01 COMMAND
In which case data:
```
<--------- 4 bytes --------->
+------+-------------+------+
# CMD  | SIZE        | 0    |
+------+-------------+------+
# [TEXT ARG] OR NULL        |
+---------------------------+
```
```c
struct command_header_t {
    uint8_t cmd;
    uint16_t size;
};
```
Text arguments are NUL terminated C-strings one after another.
#### 2.1.3. 0x02 DATA (client -> server)
Directly raw file data. Could be a whole file smaller than block size, or one of the blocks of the file. Block size is defined in the client and the server independently.
#### 2.1.4. 0x03 COMPRESSED DATA
Same as 2.1.3 but the data is gzip compressed.

### 2.2. From server
#### 2.2.1. 0x00 PING ANSWER
No data. Size = 0.
#### 2.2.2. 0x01 STATUS
```
<--------- 4 bytes --------->
+------+-------------+------+
| STAT | [SIZE]      | 0    |
+------+-------------+------+
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
#### 2.2.4. 0x03 COMPRESSED DATA
Same as 2.1.4.

## 3. Commands
From client
### 3.1. 0x00 NC - Null Command
No arguments.  
No action performed.  
**Returns**: 0x00 NS
### 3.2. 0x01 LOGIN - Log in the system
**Text argument first**: Username.<sup>2</sup>  
**Text argument second**: Password.<sup>3</sup> 
**Returns**: 0x01 LOGGEDIN or 0x04 ELOGIN
### 3.2. 0x02 LS - Directory Listing
No arguments.  
**Returns**: 0x02 LSD, or 0x05 ENODIR or 0x07 EACCESS on error.  
### 3.3. 0x03 CD - Change Directory
**Text argument**: The name or path of a directory.<sup>1</sup>  
**Returns**: 0x03 ACK on success, or 0x05 ENODIR, 0x07 EACCESS or 0x08 ESYS on error.  
### 3.4. 0x04 GET - Get File
**Text argument**: The name or path of file to get.<sup>1</sup>  
**Returns**: 0x03 ACK on success, or 0x06 NOFILE, 0x07 EACCESS or 0x08 ESYS on error.  
The client should now receive 0x02 DATA blocks from server.  
### 3.4. 0x05 PUT - Put File
**Text argument**: The name or path of file to put.<sup>1</sup>  
**Returns**: 0x03 ACK on success, or 0x07 EACCESS or 0x08 ESYS on error.  
The client should now transmit 0x02 DATA blocks to server.  
### 3.5. 0x06 ENCRYPT - Begin TLS Encryption
No arguments. Triggers TLS handshake.  
Result: The server accept()s a TLS handshake.  
Inmediately followed by a TLS connect() by the client.  

<sup>1</sup>Subject to system MAX_PATH, 4096 in Linux.  
<sup>2</sup>Subject to system max username lenth, 32 in Linux.  
<sup>3</sup>Subject to system max password lenth, infinite in Linux.  

## 4. Status
From server
### 4.1. 0x00 NS - Null Status
No data.
### 4.2. 0x01 LOGGEDIN - Log In Successful
No data.
### 4.2. 0x02 LSD - List Directory Data
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

### 4.3. 0x03 ACK - Command Acknowledge
No data. Result of succesful command.
### 4.3. 0x04 ELOGIN - Incorrect Login
No data.
### 4.4. 0x05 ENODIR - Directory does not exist
No data.
### 4.5. 0x06 ENOFILE - File does not exist
No data.
### 4.6. 0x07 EACCESS - Permission denied
No data.
### 4.7. 0x08 ESYS - Generic system error in the server
No data.

## 5. Revision History
### 5.1. Version 1.0.
Initial protocol. Basic file transfer. No login, gzip or encryption.
### 5.2. Version 1.1.
Added 0x03 COMPRESSED DATA block, and 0x06 ENCRYPT command. Backwards compatible.
### 5.3. Version 1.2.
Added 0x01 LOGIN and appropiate status. Moved the rest making this version not backwards compatible. Use only this version.

