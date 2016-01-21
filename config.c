#include "config.h"
#include "common.h"
//-------------------------------------------------------------------------------------------------

int load_config(Config* config,const char* filename)
{
 memset(config,0,sizeof(Config));
 FILE* fp=fopen(filename,"r");
 if(fp==NULL)
    return -1;
 char* line = NULL;
 size_t len = 0;
 ssize_t read=0;
 FileItem* fi=NULL;
 int fi_index=0;
 int be_string_index=-1; 
 while((read=getline(&line,&len,fp))!=-1)
      {
       if(strlen(line)<=0||line[0]=='['||line[0]=='#')
          continue;
       char* p=strchr(line,'=');
       if(p==NULL)
          continue;
       p[0]=0;
       char* key=trim(line);
       char* value=trim(p+1);
       if(strcmp(key,"base_domain")==0)
          sprintf(config->base_domain,"%s",value);
       else if(strcmp(key,"request_timeout_seconds")==0)
          config->request_timeout_seconds=atoi(value);
       else if(strcmp(key,"connection_timeout_seconds")==0)
          config->connection_timeout_seconds=atoi(value);
       else if(strcmp(key,"check_time_interval")==0)
          config->check_time_interval=atoi(value);
       else if(strcmp(key,"ap_version")==0)
          sprintf(config->ap_version,"%s",value);
       else if(strcmp(key,"aeskey")==0)
         {
          sprintf(config->aeskey,"%s",value);
         }
       else if(strcmp(key,"filename")==0)
          {
           if(fi!=NULL)
             {
              config->file_items[fi_index++]=*fi;
              free(fi);
             }
           fi=malloc(sizeof(FileItem));
           memset(fi,0,sizeof(FileItem));
           if(fi==NULL)
              break;
           be_string_index=-1;
           sprintf(fi->filename,"%s",value);
          }
       else if(strcmp(key,"begin_string")==0)
          {
           be_string_index++;
           strcpy(fi->begin_string[be_string_index],value);
          }
       else if(strcmp(key,"end_string")==0)
          {
           strcpy(fi->end_string[be_string_index],value);
	  }
       else if(strcmp(key,"trigger_command")==0)
          {
           strcpy(fi->trigger_command,value);
          }
      }//end while
 if(fi)
   {
    config->file_items[fi_index++]=*fi;
    free(fi);
   }
 if(line) free(line);
 config->file_item_count=fi_index;
 return 1;
}
//-------------------------------------------------------------------------------------------------

void print_config(Config config)
{
 printf("\n-----begin of config-----\n\n");
 printf("base_domain:%s\nrequest_timeout_seconds:%d\nconnection_timeout_seconds:%d\n\
check_time_interval:%d\nap_version:%s\naeskey:%s\n", 
         config.base_domain,config.request_timeout_seconds,
         config.connection_timeout_seconds,
         config.check_time_interval,config.ap_version,config.aeskey);
 int i=0;
 for(;i<config.file_item_count;i++)
    {
     printf("%s,%s:\n",config.file_items[i].filename,
                       config.file_items[i].trigger_command);
     int k=0;
     for(;k<FILE_MAX_SECTION;k++)
        {
         if(strlen(config.file_items[i].begin_string[k])>0)
            printf("\t%s => %s\n",config.file_items[i].begin_string[k],config.file_items[i].end_string[k]);
        }//end k
    }//end for i
 printf("\n-----end of config-----\n");
}
//-------------------------------------------------------------------------------------------------

int check_config(Config* config)
{
 if(config->connection_timeout_seconds<=0)
    config->connection_timeout_seconds=DEFAULT_CONNECTION_TIMEOUT_SECONDS;
 if(config->request_timeout_seconds<=0)
    config->request_timeout_seconds=DEFAULT_REQUEST_TIMEOUT_SECONDS;
 return 1;
}
//-------------------------------------------------------------------------------------------------
