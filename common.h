#ifndef COMMONH
#define COMMONH
#include <string.h>
#include <stdio.h>
//-------------------------------------------------------------------------------------------------
char* trim(char* s);
void md5(char* string,unsigned char *p);
void md52string(unsigned char* m,char* string);
int get_mac(unsigned char* mac);
//-------------------------------------------------------------------------------------------------
#endif
