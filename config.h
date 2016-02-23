#ifndef CONFIGH
#define CONFIGH
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//-------------------------------------------------------------------------------------------------
#define FILE_MAX_SECTION 1
#define FILE_MAX_NUMBER 8
#define FILE_NAME_MAX_SIZE 128
#define TRIGGER_COMMAND_MAX_SIZE 64
#define DEFAULT_REQUEST_TIMEOUT_SECONDS 30
#define DEFAULT_CONNECTION_TIMEOUT_SECONDS 10

#define FILES_MD5_EXPIRE_TIME 90000

#define AESENCODE
#define POST_DATA_MAX_SIZE 128*1024
#define RECEIVE_DATA_MAX_SIZE 128*1024

#define RELOAD_CONFIG "/tmp/cloudgate_reload_config"
//-------------------------------------------------------------------------------------------------
typedef struct FileItem_s
{
 char filename[FILE_NAME_MAX_SIZE];
 char begin_string[FILE_MAX_SECTION][32];
 char end_string[FILE_MAX_SECTION][32];
 unsigned char md5[16];
 time_t last_modify_time;
 char trigger_command[TRIGGER_COMMAND_MAX_SIZE];
 char trigger_unix_socket[FILE_NAME_MAX_SIZE];
}FileItem;

typedef struct Config_s
{
 char base_domain[64];
 unsigned short request_timeout_seconds;
 unsigned short connection_timeout_seconds;
 uint32_t check_time_interval;
 char ap_version[16];
 char aeskey[32];
 char ap_reset_tag[FILE_NAME_MAX_SIZE];
 FileItem file_items[FILE_MAX_NUMBER];
 unsigned short file_item_count;
}Config;

//-------------------------------------------------------------------------------------------------
int load_config(Config* config,const char* filename);
int check_config(Config* config);
void print_config(Config config);
//-------------------------------------------------------------------------------------------------
#endif
