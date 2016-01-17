#ifndef BASE64H
#define BASE64H
#include <string.h>
#include <stdio.h>
//-------------------------------------------------------------------------------------------------
char *base64_encode(const char *data,size_t input_length,size_t *output_length);
char *base64_decode(const char *data,size_t input_length,size_t *output_length);
void build_decoding_table();
void base64_cleanup();
//-------------------------------------------------------------------------------------------------
#endif
