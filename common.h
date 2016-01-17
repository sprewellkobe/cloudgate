#ifndef COMMONH
#define COMMONH
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
//-------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------
char* trim(char* s);
void md5(char* from,char* to,unsigned char* p);
char* md52string(unsigned char* m,char* string);
int get_mac(unsigned char* mac);
void mac2string(unsigned char* mac,char* string);
int get_files_md5(void* config_,unsigned char* md);
char* read_file(char* filename,size_t* file_length);
int write_file(char* filename,char* content,uint32_t content_length);
void do_aes(char* in,char* out,char* key);
//-------------------------------------------------------------------------------------------------
#endif
