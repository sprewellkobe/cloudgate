#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"
#include "config.h"
#include "mycurl.h"
#include "cjson.h"
#include "base64.h"

#ifdef BUILD_MIPS
#include "nbos_hal_api.h"
#include "nbos_log.h"
#include "amu_lib.h"

#define  D_CLOUDGATE_LOG_FILE		"/var/log/cloudgate.log"
#define  D_CLOUDGATE_LOG_LEVEL		LOG_INFO
#endif

//-------------------------------------------------------------------------------------------------
typedef struct Result_s
{
 char result[16];
 char files[FILE_MAX_NUMBER][64];
 unsigned short file_count;
 char* files_content[FILE_MAX_NUMBER];
 char reason[16];
}Result;
//-------------------------------------------------------------------------------------------------

void print_result(Result* result)
{
 printf("%s:%s\n",result->result,result->reason);
 int i=0;
 for(;i<result->file_count;i++)
    {
     if(result->files[i]==NULL)
        continue;
     printf("%s:\n",result->files[i]);
     if(result->files_content[i]!=NULL)
        printf("[%s]\n",result->files_content[i]);
    }
}
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

void free_result(Result* result)
{
 int i=0;
 for(;i<FILE_MAX_NUMBER;i++)
    {
     if(result->files_content[i]!=NULL)
       {
        free(result->files_content[i]);
	result->files_content[i]=NULL;
       }
    }
}
//-------------------------------------------------------------------------------------------------

int update_local_files(Config* config,Result* result)
{
 int i=0;
 build_decoding_table();
 for(;i<result->file_count;i++)
    {
     size_t file_length=0;
     char* content=base64_decode(result->files_content[i],strlen(result->files_content[i]),&file_length);
     if(write_file(result->files[i],content,file_length)<0)
       {
        free(content);
        break;
       }
     free(content);
     int k=0;
     for(;k<config->file_item_count;k++)
        {
         if(strcmp(config->file_items[k].filename,result->files[i])==0)
           {
            if(strlen(config->file_items[k].trigger_command)>0)
              {
               system(config->file_items[k].trigger_command);
               #ifdef MYDEBUG
               printf("triggered %s\n",config->file_items[k].trigger_command);
               #endif
              }
            if(strlen(config->file_items[k].trigger_unix_socket)>0)
              {
               send_message_to_unix_socket(config->file_items[k].trigger_unix_socket,"ok",2);
               #ifdef MYDEBUG              
               printf("triggered %s\n",config->file_items[k].trigger_unix_socket);
               #endif  
              }
            break;
           }
        }//end for k
    }//end for i
 base64_cleanup();
 if(i<result->file_count)
    return -1;
 return 1;
}
//-------------------------------------------------------------------------------------------------

int check_config_build_post_data(Config* config,char* mac_string,char* md5_string,char* post_data)
{
 cJSON* root;
 cJSON* files;
 cJSON* item;
 root=cJSON_CreateObject();

 cJSON_AddStringToObject(root,"apid",mac_string);
 cJSON_AddStringToObject(root,"checksum",md5_string);
 cJSON_AddStringToObject(root,"version",config->ap_version);

 //added
 char temp[64];
 get_wtp_ip(config,temp);
 cJSON_AddStringToObject(root,"wtp_ip",temp);
 get_primary_ver(config,temp);
 cJSON_AddStringToObject(root,"primary_ver",temp);
 get_factory_ver(config,temp);
 cJSON_AddStringToObject(root,"factory_ver",temp);
 get_backup_ver(config,temp);
 cJSON_AddStringToObject(root,"backup_ver",temp);
 get_uplinktype(config,temp);
 cJSON_AddStringToObject(root,"uplinktype",temp);
 cJSON_AddNumberToObject(root,"ternum",get_ternum(config));

 cJSON_AddItemToObject(root,"files",files=cJSON_CreateArray());
 int i=0;
 for(;i<config->file_item_count;i++)
    {
     cJSON_AddItemToArray(files,item=cJSON_CreateObject());
     cJSON_AddStringToObject(item,"filename",config->file_items[i].filename);
     char tmp[64];
     md52string(config->file_items[i].md5,tmp);
     cJSON_AddStringToObject(item,"checksum",tmp);
     //sprintf(tmp,"%lu",config->file_items[i].last_modify_time);
     cJSON_AddNumberToObject(item,"timestamp",config->file_items[i].last_modify_time);
    }
 char* out=cJSON_PrintUnformatted(root);
 #ifdef MYDEBUG
 printf("post_data1:%lu:%s\n",strlen(out),out);
 #endif
 #ifdef AESENCODE
 size_t out_length=strlen(out);
 char* out2=calloc(out_length*8,sizeof(char));
 do_aes_encrypt(out,out2,config->aeskey);
 free(out);
 out=out2;
 #endif
 strcpy(post_data,out);
 #ifdef MYDEBUG
 printf("post_data2:%lu:%s\n",strlen(post_data),post_data);
 #endif
 free(out);
 cJSON_Delete(root);
 return 1;
}
//-------------------------------------------------------------------------------------------------

int update_server_config_build_post_data(Config* config,char* mac_string,
                                         Result* result,char* post_data)
{
 cJSON* root;
 cJSON* files;
 cJSON* item;
 root=cJSON_CreateObject();
 cJSON_AddStringToObject(root,"apid",mac_string);
 cJSON_AddStringToObject(root,"version",config->ap_version);
 cJSON_AddItemToObject(root,"files",files=cJSON_CreateArray());
 int i=0;
 for(;i<result->file_count;i++)
    {
     cJSON_AddItemToArray(files,item=cJSON_CreateObject());
     char* filename=result->files[i];
     cJSON_AddStringToObject(item,"filename",filename);

     size_t file_length=0;
     char* content=read_file(filename,&file_length);
     if(content==NULL)
        break;

     size_t base64_code_length=0;
     char* base64_code=base64_encode(content,file_length,&base64_code_length);
     cJSON_AddStringToObject(item,"filecontent",base64_code);
     free(base64_code);

     struct stat st;
     if(stat(filename,&st)!=0)
       {
        free(content);
        break;
       }
     cJSON_AddNumberToObject(item,"timestamp",st.st_mtime);
    
     unsigned char digest[16];
     md5(content,content+file_length,digest);
     char tmp[64];
     md52string(digest,tmp);
     cJSON_AddStringToObject(item,"checksum",tmp);
     
     free(content);    
    }//end for
 char* out=cJSON_PrintUnformatted(root);
 #ifdef AESENCODE
 #ifdef MYDEBUG
 //printf("post_data_o:[%s]\n",out);
 #endif
 size_t out_length=strlen(out);
 char* out2=calloc(out_length*8,sizeof(char));
 do_aes_encrypt(out,out2,config->aeskey);
 free(out);
 out=out2;
 #endif
 strcpy(post_data,out);
 #ifdef MYDEBUG
 printf("post_data_d:[%s]\n",post_data);
 #endif
 free(out);
 cJSON_Delete(root);
 return 1;
}
//-------------------------------------------------------------------------------------------------

int parse_result(char* received,char* message,Result* result)
{
 memset(result,0,sizeof(Result));
 cJSON* root=cJSON_Parse(received);
 if(root==NULL)
    return -1;
 int status=0;
 cJSON* item;
 item=cJSON_GetObjectItem(root,"status");
 if(item==NULL)
   {
    cJSON_Delete(root);
    return -7;
   }
 status=item->valueint;
 item=cJSON_GetObjectItem(root,"message");
 if(item==NULL)
   {
    cJSON_Delete(root);
    return -8;
   }
 strcpy(message,item->valuestring);
 cJSON* root2=cJSON_GetObjectItem(root,"data");
 if(status!=0||root2==NULL)
   {
    cJSON_Delete(root);
    return -3;
   }

 item=cJSON_GetObjectItem(root2,"result");
 if(item==NULL)
   {
    cJSON_Delete(root); 
    return -2;
   }
 strcpy(result->result,item->valuestring);
 item=NULL;
 item=cJSON_GetObjectItem(root2,"files");
 if(item!=NULL)
   {
    result->file_count=cJSON_GetArraySize(item);
    int i=0;
    for(;i<result->file_count;i++)
       {
        
        cJSON* file=cJSON_GetArrayItem(item,i);
        file=file->child;
        strcpy(result->files[i],file->string);
        size_t file_length=strlen(file->valuestring);
        result->files_content[i]=malloc(file_length+1);
        strcpy(result->files_content[i],file->valuestring);
        result->files_content[i][file_length]=0;
       }
   }//end if files
 item=NULL;
 item=cJSON_GetObjectItem(root2,"filenames");
 if(item==NULL)
    item=cJSON_GetObjectItem(root2,"updated_filenames");
 if(item!=NULL)
   {
    result->file_count=cJSON_GetArraySize(item);
    int i=0;
    for(;i<result->file_count;i++)
       {
        cJSON* file=cJSON_GetArrayItem(item,i);
        strcpy(result->files[i],file->valuestring);
       }
   }//end if filenames updated_filenames
 item=NULL;
 item=cJSON_GetObjectItem(root2,"reason");
 if(item!=NULL)
    strcpy(result->reason,item->valuestring);
 cJSON_Delete(root); 
 return 1;
}
//-------------------------------------------------------------------------------------------------

int loop_handle(Config* config)
{
 char mac_string[32];

 memset(mac_string, 0, sizeof(mac_string));
 if(get_mac_str(mac_string)<0)
   {
    printf("failed to get mac, errno:%d\n",errno);
    return -1;
   }

 unsigned char md5[16];
 if(get_files_md5((void*)config,md5)<0)
   {
    printf("failed to get md5, errno:%d\n",errno);
    return -1;
   }
 char md5_string[64];
 memset(md5_string,0,64);
 md52string(md5,md5_string);
 char url[256];
 sprintf(url,"http://%s/check_config?apid=%s&checksum=%s&version=%s",
         config->base_domain,mac_string,md5_string,config->ap_version);

 static char post_data[POST_DATA_MAX_SIZE];
 check_config_build_post_data(config,mac_string,md5_string,post_data);
 static char received[RECEIVE_DATA_MAX_SIZE];
 Result result;
 memset(&result,0,sizeof(result));
 int rc=-99;
 int pc=0;
 if((rc=do_wget(config,url,post_data,received))!=200)
   {
    #ifdef MYDEBUG
    printf("%lu curl failed %d %s\n",time(NULL),rc,url);
    #endif
    return -1;
   }
 #ifdef AESENCODE
 #ifdef MYDEBUG
 printf("received:%s\n",received);
 #endif
 char* tmp=malloc(RECEIVE_DATA_MAX_SIZE);
 do_aes_decrypt(received,tmp,config->aeskey);
 sprintf(received,"%s",tmp);
 free(tmp);
 #endif 
 #ifdef MYDEBUG
 printf("received2:%s\n",received);
 #endif
 char message[32];
 memset(message,0,32);
 if((pc=parse_result(received,message,&result))<0)
   {
    #ifdef MYDEBUG
    printf("%lu %s, failed to parse %s\n",time(NULL),message,received);
    #endif
   }
 if(strcmp(result.result,"nothingtodo")==0)//when cloud config == ap config
   {
    printf("%lu nothing to do\n",time(NULL));
    return 2;
   }
 if(strcmp(result.result,"apupdate")==0)//when server is newer
   {
    if(update_local_files(config,&result)>0)
      {
       printf("%lu ap updated:\n",time(NULL));
       unsigned short i=0;
       for(;i<result.file_count;i++)
           printf("\t%s\n",result.files[i]);
      }
    else
       printf("%lu ap update file failed, errno:%d\n",time(NULL),errno);
    free_result(&result);
    return 3;
   }
 if(strcmp(result.result,"serverupdate")==0)//when ap is newer
   {
    sprintf(url,"http://%s/update_server_config?apid=%s",config->base_domain,mac_string);
    update_server_config_build_post_data(config,mac_string,&result,post_data);
    if((rc=do_wget(config,url,post_data,received))!=200)
      {
       printf("%lu server update failed2 %d\n",time(NULL),rc);
       free_result(&result);
       return -5;
      }
    #ifdef AESENCODE
    #ifdef MYDEBUG
    printf("received:%s\n",received);
    #endif
    char* tmp=malloc(RECEIVE_DATA_MAX_SIZE);
    do_aes_decrypt(received,tmp,config->aeskey);
    sprintf(received,"%s",tmp);
    free(tmp);
    #endif
    memset(message,0,32);
    if((pc=parse_result(received,message,&result))<0)
      {
       #ifdef MYDEBUG
       printf("%lu %s,failed to parse2 %s\n",time(NULL),message,received);
       free_result(&result);
       return -6;
       #endif
      }
    if(strcmp(result.result,"ok")==0)
      {
       printf("%lu server updated:\n",time(NULL));
       int i=0;
       for(;i<result.file_count;i++)
	   printf("\t%s\n",result.files[i]);
      }
    else if(strcmp(result.result,"fail")==0)
      {
       printf("%lu server update failed1 %s\n",time(NULL),result.reason);
      }
    else
       printf("%lu server update failed3\n",time(NULL));
    free_result(&result);
    return 4;
   }
 return -7; 
}
//-------------------------------------------------------------------------------------------------

int set_ap_leave_all_groups(Config* config)
{
 char mac_string[32];
 memset(mac_string, 0, sizeof(mac_string));
 get_mac_str(mac_string);
 char buffer1[64];
 sprintf(buffer1,"apid=%s&opt=group_leave",mac_string);
 char* get_data=buffer1;
 #ifdef AESENCODE
 char buffer2[512];
 do_aes_encrypt(buffer1,buffer2,config->aeskey);
 get_data=buffer2;
 #endif
 char url[640];
 sprintf(url,"http://%s/grp?msg=%s",config->base_domain,get_data);
 int rc=0;
 char received[RECEIVE_DATA_MAX_SIZE];
 if((rc=do_wget(config,url,NULL,received))!=200)
   {
    printf("%lu\tset group leave failed %d\n",time(NULL),rc);
    return -1;
   }
 #ifdef MYDEBUG
 printf("%lu\tset ap left all groups\n",time(NULL));
 #endif
 return 1;
}
//-------------------------------------------------------------------------------------------------

void test(Config* config)//only for test
{
 int rv=0;
 /*
 unsigned char md5[16];
 char md5_string[32];
 rv=get_files_md5((void*)config,md5);
 if(rv<0)
    printf("md5 failed %d\n",rv);
 else
   {
    md52string(md5,md5_string);
    printf("[%s]\n",md5_string);
   }

 unsigned char mac[6];
 get_mac(mac);
 char mac_string[32];
 mac2string(mac,mac_string);
 char post_data[1024];
 check_config_build_post_data(config,mac_string,md5_string,post_data);
 */

 /*build_decoding_table();
 char* input="abc";
 size_t output_length,output2_length; 
 char* output=base64_encode(input,strlen(input),&output_length);
 printf("base64 1:%s\n",output);
 char* output2=base64_decode(output,output_length,&output2_length);
 printf("base64 2:%s\n",output2);
 free(output2);
 free(output);
 base64_cleanup();*/
 
 char* s2="{\"result\":\"apupdate\",\"files\":[{\"/tmp/aaa\":\"YWJj\"},{\"/tmp/bbb\":\"YWJj\"}]}";
 char s[256];
 sprintf(s,"{\"status\":1,\"message\":\"kobe\",\"data\":%s}",s2);
 char message[32];
 memset(message,0,32);
 Result result;
 rv=parse_result(s,message,&result);
 if(rv>0)
   {
    print_result(&result);
    /*if(strcmp(result.result,"apupdate")==0)
      {
       rv=update_local_files(config,&result);
       printf("local files updated %d\n",rv);
      }*/
   }
 else
    printf("parse failed %d %s %s\n",rv,message,s);
 free_result(&result);

 /*
 char* s="{\"result\":\"apupdate\",\"files\":[{\"/etc/kisslink\":\"c3NzMjIyMnNzcwo=\"}]}";
 char out[1024];
 int rt=do_aes_encrypt(s,out,config->aeskey);
 if(rt>0)
    printf(":>:\%s\n",out);
 else
    printf("failed %d\n",rt);

 char out2[1024];
 rt=do_aes_decrypt(out,out2,config->aeskey);
 if(rt>0)
    printf(":<:\%s\n",out2);
 else
    printf("failed %d\n",rt);*/
 exit(0);
}
//-------------------------------------------------------------------------------------------------

int main(int argc,char* argv[])
{
 if(argc!=2||(strcmp(argv[1],"-h")==0||strcmp(argv[1],"-help")==0))
   {
    display_usage();
    return 0;
   }
#ifdef BUILD_MIPS
 if (nbos_log_init("cloudgate", D_CLOUDGATE_LOG_LEVEL, D_CLOUDGATE_LOG_FILE) != 0) {
	 printf("cloudgate: log file init fails, exit...\n");
    return 0;
 }
 nbos_log_set_size(3*INFO_FILE_SIZE_LIMIT);
#endif

 Config config;
 if(load_config(&config,argv[1])<0)
   {
    printf("failed to load %s, errno:%d\n",argv[1],errno);
    return -1;
   }
 #ifdef MYDEBUG
 print_config(config);
 #endif

#ifdef BUILD_MIPS
 /*start amu watchdog*/
 Amu_Start_Processing();
#endif

 //test(&config);
 int i=0;
 while(1<3)
      {
       struct stat st;
       if(stat((char*)RELOAD_CONFIG,&st)==0)//reload config if need
         {
          Config tc;
          if(load_config(&tc,argv[1])>0)
            {
             memcpy(&config,&tc,sizeof(config));
             printf("%lu\tconfig reloaded\n",time(NULL));
             #ifdef MYDEBUG
             print_config(config);
             #endif
            }
          unlink(RELOAD_CONFIG);
          continue;
         }//end if
       memset(&st,0,sizeof(st));
       if(strlen(config.ap_reset_tag)>0&&
          stat(config.ap_reset_tag,&st)==0)//when ap just reset
         {
          if(set_ap_leave_all_groups(&config)>0)
            {
             #ifdef MYDEBUG
             printf("%lu\tset ap left all groups\n",time(NULL));
             #endif
             unlink(config.ap_reset_tag);
            }
          continue;
         }//end if
       loop_handle(&config);
       sleep(config.check_time_interval);
      }//end while true
 i=0;
 return 0;
}
//---------------------------------------------------------------------------------------------------
