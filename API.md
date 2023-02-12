# libarftransfer API specification Version 1.3
## 1. Functions
### 1.1 Common
#### 1.1.1. int aft_init()
Init arftransfer, allocate stuff  
**Return**: 0 or -1 on error  
#### 1.1.2. void aft_cleanup()
Clean arftransfer, deallocate stuff  
#### 1.1.3. int aft_get_last_error()
Get last arftransfer error  
**Return**: Error code  
#### 1.1.4. const char* aft_get_last_error_str()
Get last arftransfer error as string  
**Return**: Error string  
#### 1.1.5. int aft_close(int fd)
Close socket  
**fd**: Socket  
**Return**: 0 or -1 on error  
#### 1.1.6. int aft_send_data(int fd, const char *data, dsize_t size)
Send DATA block  
**fd**: Socket  
**data**: Data to send  
**size**: Size of data  
**Return**: 0 or -1 on error  
#### 1.1.7. int aft_send_cdata(int fd, const char *data, dsize_t size)
Send CDATA gzip compressed block  
**fd**: Socket  
**data**: Data to deflate and send  
**size**: Size of data  
**Return**: 0 or -1 on error  
### 1.1. Client
#### 1.1.1. int aft_open(const char *host, uint16_t port)
Connect to host  
**host**: Host to connect to  
**port**: Port to connect to  
**Returns**: Socket fd or -1  
#### 1.1.2. int aft_ping(int fd, struct timespec *rtt)
Do echo block and receive answer, measuring round trip time  
**fd**: Socket  
**rtt**: timespec to store round trip time  
**Return**: 0 or -1 on error  
#### 1.1.3. int aft_login(int fd, const char *user, const char *passwd)
Attempt login  
**fd**: Socket  
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

