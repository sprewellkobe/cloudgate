#ifndef MYCURLH
#define MYCURLH
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>
#include "config.h"
//-------------------------------------------------------------------------------------------------
int do_wget(Config* config,char* url,char* post_data,char* received);
//-------------------------------------------------------------------------------------------------
#endif
