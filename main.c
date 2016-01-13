#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "common.h"
#include "config.h"
#include "mycurl.h"
//-------------------------------------------------------------------------------------------------
typedef struct Result_s
{
 char result[16];
 char files[FILE_MAX_NUMBER][64];
}Result;
//-------------------------------------------------------------------------------------------------

void display_usage()
{
 printf(
"usage:\n\
    cloudgate config_filename\n\
author:\n\
    kobe\n\
build:\n\
    %d\n",BUILDVERSION);
}
//-------------------------------------------------------------------------------------------------

int get_files_md5(Config* config,unsigned char* md5)
{
 return 1;
}
//-------------------------------------------------------------------------------------------------

int build_post_data(Config* config,char* mac_string,char* md5_string,char* post_data)
{
 return 1;
}
//-------------------------------------------------------------------------------------------------

int parse_result(char* received,Result* result)
{
 return 1;
}
//-------------------------------------------------------------------------------------------------

//
int loop_handle(Config* config)
{
 unsigned char mac[6];
 if(get_mac(mac)<0)
   {
    printf("failed to get mac, errno:%d\n",errno);
    return -1;
   }
 char mac_string[32];
 sprintf(mac_string,"%x:%x:%x:%x:%x:%x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

 unsigned char md5[16];
 if(get_files_md5(config,md5)<0)
   {
    printf("failed to get md5, errno:%d\n",errno);
    return -1;
   }
 char md5_string[32];
 md52string(md5,md5_string);
 char url[256];
 sprintf(url,"http://%s/check_config?apid=%s&checksum=%s&version=%s",
         config->base_domain,mac_string,md5_string,config->ap_version);

 char post_data[4096];
 build_post_data(config,mac_string,md5_string,post_data);
 char received[1024];
 Result result;
 if(do_wget(config,url,post_data,received)==200&&parse_result(received,&result)>0)
   {
    
   } 
 return 1; 
}
//-------------------------------------------------------------------------------------------------

int main(int argc,char* argv[])
{
 if(argc!=2||(strcmp(argv[1],"-h")==0||strcmp(argv[1],"-help")==0))
   {
    display_usage();
    return 0;
   }
 Config config;
 if(load_config(&config,argv[1])<0)
   {
    printf("failed to load %s, errno:%d\n",argv[1],errno);
    return -1;
   }
 #ifdef MYDEBUG
 print_config(config);
 #endif
 
 static char rs[81920];
 int rv=do_wget(&config,"http://www.baidu.com",NULL,rs);
 printf("%s\n",rs);
 while(0)
      {
       loop_handle(&config);
       sleep(config.check_time_interval);
      }
 return 0;
}
