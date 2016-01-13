#ifndef CONFIGH
#define CONFIGH
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//-------------------------------------------------------------------------------------------------
#define FILE_MAX_SECTION 8
#define FILE_MAX_NUMBER 4

#define DEFAULT_REQUEST_TIMEOUT_SECONDS 30
#define DEFAULT_CONNECTION_TIMEOUT_SECONDS 10
//-------------------------------------------------------------------------------------------------
typedef struct FileItem_s
{
 char filename[32];
 char begin_string[FILE_MAX_SECTION][32];
 char end_string[FILE_MAX_SECTION][32];
}FileItem;

typedef struct Config_s
{
 char base_domain[64];
 unsigned short request_timeout_seconds;
 unsigned short connection_timeout_seconds;
 uint32_t check_time_interval;
 char ap_version[16];
 char aeskey[16];
 FileItem file_items[FILE_MAX_NUMBER];
 unsigned short file_item_count;
}Config;

//-------------------------------------------------------------------------------------------------
int load_config(Config* config,const char* filename);
int check_config(Config* config);
void print_config(Config config);
//-------------------------------------------------------------------------------------------------
#endif
