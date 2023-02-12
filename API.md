# libarftransfer API specification Version 1.3
## 1. Functions
### 1.1. Client
#### 1.1.1. int aft_open(const char *host, uint16_t port)
Connect to host
**host**: Host to connect to
**port**: Port to connect to
**Returns**: Socket fd or -1
#### 1.1.2. int aft_ping(int fd, struct timespec *rtt)
Do echo block and receive answer, measuring round trip time
**Returns**: RTT in ms or zeroed timespec on error
#### 1.1.3. int aft_login(const char *user, const char *passwd)
Attempt login
**user**: Username
**passwd**: Password
**Returns**: 0 or -1 on error
#### 1.1.4. int aft_pwd(char *path)
Get working directory
**Returns**: 0 or -1 on error
#### 1.1.4. int aft_ls(dir_t *dir)
List directory
**Returns**: 0 or -1 on error
#### 1.1.5. int aft_cd(const char *path)
Change directory
**Returns**: 0 or -1 on error
#### 1.1.6. int aft_get(const char *path, char *data, size_t size)
Get file.
**Returns**: size of data or -1 on error
#### 1.1.7. int aft_put(const char *path, const char *data, size_t size)
Put file.
**Returns**: size of data or -1 on error
#### 1.1.8. int aft_encrypt()
**Returns**: Nothing, immediately triggers TLS handshake
### 1.2. Server
#### 1.2.1. aft_listen()
#### 1.2.2. aft_accept()
#### 1.2.4. aft_recv_block()
#### 1.2.5. aft_parse_cmd()
#### 1.2.6. aft_parse_data()
### 1.3 Common
#### 1.3.1. aft_send_data()
#### 1.3.2. aft_send_cdata()
#### 1.3.3. aft_close()
#### 1.3.4. aft_get_error()