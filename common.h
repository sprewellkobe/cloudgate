#ifndef COMMONH
#define COMMONH
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
//-------------------------------------------------------------------------------------------------
char* trim(char* s);
void md5(char* from,char* to,unsigned char* p);
char* md52string(unsigned char* m,char* string);
int get_mac(unsigned char* mac);
int get_mac_str(char * strmac);
void mac2string(unsigned char* mac,char* string);
int get_files_md5(void* config_,unsigned char* md);
char* read_file(char* filename,size_t* file_length);
int write_file(char* filename,char* content,uint32_t content_length);
void write_to_hex(char* in,size_t in_length,char* out);
void read_from_hex(char*in,char* out,size_t* out_length);
int do_aes_encrypt(char* in,char* out,char* key_);
int do_aes_decrypt(char* in,char* out,char* key_);
int send_message_to_unix_socket(char* socket_name,char* message,size_t length);

void get_wtp_ip(void* config_,char* string);
void get_primary_ver(void* config_,char* string);
void get_factory_ver(void* config_,char* string);
void get_backup_ver(void* config_,char* string);
void get_uplinktype(void* config_,char* string);
unsigned int get_ternum(void* config_);
void get_uptime(void *config_, char *strtime);
//-------------------------------------------------------------------------------------------------
#endif
