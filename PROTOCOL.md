# AFT Protocol Specification - Version 1.3
A file transfer protocol over TCP/IP. One single connection client -> server, optionally supports gzip compression and TLS encryption. No checksum check because TCP already does it.

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
Current protocol version is 1.3 (0x13).

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
Directly raw file data. Could be a whole file smaller than block size, or one of the blocks of the file. Block size is defined in the client and the server independently. THe maximum block size is 65535 (0xffff).
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
**Returns**: NS
### 3.2. 0x01 LOGIN - Log in the system
**Text argument first**: Username.<sup>2</sup>  
**Text argument second**: Password.<sup>3</sup> 
**Returns**: LOGGED or ELOGIN
### 3.3. 0x02 PWD - Get Working Directory
No arguments. 
**Returns**: PWDD or EANON
### 3.4. 0x03 LS - Directory Listing
No arguments.  
**Returns**: LSD or EANON
### 3.5. 0x04 CD - Change Directory
**Text argument**: The name or path of a directory.<sup>1</sup>  
**Returns**: ACK on success, or EANON, ENODIR, EACCESS or ESYS on error.  
### 3.6. 0x05 GET - Get File
**Text argument**: The name or path of file to get.<sup>1</sup>  
**Returns**: ACK on success, or EANON, NOFILE, EACCESS or ESYS on error.  
The client should now receive 0x02 DATA blocks from server.  
### 3.7. 0x06 PUT - Put File
**Text argument**: The name or path of file to put.<sup>1</sup>  
**Returns**: ACK on success, or EANON, EACCESS or ESYS on error.  
The client should now transmit (C)DATA blocks to server.  
### 3.8. 0x07 RM - Remove file or directory
**Text argument**: File or directory path to remove.
**Returns**: ACK on success, or EANON, ENOFILE, ENODIR, ENOACCESS or ESYS on error.
### 3.9. 0x08 ENCRYPT - Begin TLS Encryption
No arguments. Triggers TLS handshake.  
Result: The server accept()s a TLS handshake.  
Inmediately followed by a TLS connect() by the client. 

<sup>1</sup>Subject to system MAX_PATH, 4096 in Linux.  
<sup>2</sup>Subject to system max username lenth, 32 in Linux.  
<sup>3</sup>Subject to system max password lenth, infinite in Linux.  


## 4. Status
From server
### 4.1.  0x00 NS - Null Status
No data.
### 4.2.  0x01 ACK - Command Acknowledge
No data. Result of succesful command.
### 4.3.  0x02 PWDD - Get Working Directory Data
Data contains NUL terminated C-string of the current directory
### 4.4.  0x03 LSD - List Directory Data
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

### 4.5.  0x04 ELOGIN - Error Incorrect Login
No data.
### 4.6.  0x05 EANON - Error Login Required
No data. Triggered by data commands. 
### 4.7.  0x06 ENODIR - Error Directory does not exist
No data.
### 4.8.  0x07 ENOFILE - Error File does not exist
No data.
### 4.9.  0x08 EACCESS - PError ermission denied
No data.
### 4.10. 0x09 ESYS - Generic system error in the server
No data.
### 4.11. 0x0a ENOTIMPL - Error Not Implemented 

## 5. Revision History
### 5.1. Version 1.0.
Initial protocol. Basic file transfer. No login, gzip or encryption.
### 5.2. Version 1.1.
Added COMPRESSED DATA block, and ENCRYPT command. Backwards compatible.
### 5.3. Version 1.2.
Added LOGIN and appropiate status. Not backwards compatible.
### 5.4. Version 1.3.
Added PWD and CLOSE commands, and PWDD and EANON status. Not backwards compatible. Use only this version.
### 5.5. Version 1.4.
Removed CLOSE cmd and LOGGED status, replaced with the new RM cmd and ACK for LOGIN.

## Appendix A. Command and status cheat sheet
```
     CMD         STAT         ESTAT
0x00 NC     0x00 NS
0x01 LOGIN  0x01 ACK     0x04 ELOGIN
0x02 PWD    0x02 PWDD    0x05 EANON
0x03 LS     0x03 LSD     0x05 EANON    
0x04 CD     0x01 ACK     0x05 EANON,  0x06 ENODIR,                0x08 EACCESS, 0x09 ESYS
0x05 GET    0x01 ACK     0x05 EANON,                0x07 ENOFILE, 0x08 EACCESS, 0x09 ESYS
0x06 PUT    0x01 ACK     0x05 EANON,                              0x08 EACCESS, 0x09 ESYS
0x07 RM     0x01 ACK     0x05 EANON,  0x06 ENODIR,  0x07 ENOFILE, 0x08 EACCESS, 0x09 ESYS
0x08 ENCRYPT <accept TLS>
```
