#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "md5.h"
#include "config.h"
#include "base64.h"
#include <openssl/aes.h>
//-------------------------------------------------------------------------------------------------
static unsigned char old_md5[16];
static FileItem old_file_items[FILE_MAX_NUMBER];
//-------------------------------------------------------------------------------------------------

char* trim(char* s)
{
 if(s==NULL)
    return NULL;
 int l=strlen(s);
 if(l==0)
    return s;
 char* e=s+l-1;
 while(*s!=0&&(*s==' '||*s=='\t'||*s=='\n'||*s=='\r'))
       s++;
 while(e>s&&(*e==' '||*e=='\t'||*e=='\n'||*e=='\r'))
      {
       *e=0;
       e--;
      }
 return s;
}
//-------------------------------------------------------------------------------------------------

void md5(char* from,char* to,unsigned char *m)
{
 MD5_CTX md5;
 MD5Init(&md5);
 MD5Update(&md5,(unsigned char*)from,to-from);
 MD5Final(&md5,m);
}
//-------------------------------------------------------------------------------------------------

char* md52string(unsigned char* m,char* string)
{
 int i=0;
 for(;i<16;i++)
     string=string+sprintf(string,"%02x",m[i]);
 return string;
}
//-------------------------------------------------------------------------------------------------

int get_mac(unsigned char* mac)
{
 memset(mac,0,6);
 return 1;
}
//--------------------------------------------------------------------------------------------------

void mac2string(unsigned char* mac,char* string)
{
 sprintf(string,"%02x:%02x:%02x:%02x:%02x:%02x",
         mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}
//--------------------------------------------------------------------------------------------------

char* read_file(char* filename,size_t* file_length)
{
 struct stat st;
 if(stat(filename,&st)!=0)
    return NULL;
 *file_length=st.st_size;
 FILE* fp=fopen(filename,"r");
 if(fp==NULL)
    return NULL;
 char* content=(char*)malloc(*file_length);
 if(content==NULL)
   {
    fclose(fp);
    return NULL;
   }
 if(fread(content,1,*file_length,fp)!=*file_length)
   {
    fclose(fp);
    free(content);
    return NULL;
   }
 fclose(fp);
 return content;
}
//--------------------------------------------------------------------------------------------------

int write_file(char* filename,char* content,uint32_t content_length)
{
 FILE* fp=fopen(filename,"w");
 if(fp==NULL)
    return -1;
 if(fwrite(content,1,content_length,fp)!=content_length)
   {
    fclose(fp);
    return -2;
   }
 fclose(fp);
 return 1;
}
//--------------------------------------------------------------------------------------------------

int get_files_md5(void* config_,unsigned char* md)
{
 if(config_==NULL)
    return -1;
 Config* config=(Config*)config_;
 time_t biggest_last_access_time=0;
 int i=0;
 for(;i<config->file_item_count;i++)
    {
     struct stat st;
     if(stat(config->file_items[i].filename,&st)!=0)
        return -2;
     time_t lat=st.st_mtime;
     config->file_items[i].last_modify_time=lat;
     biggest_last_access_time=biggest_last_access_time>lat?biggest_last_access_time:lat;
    }
 if((old_md5[0]!=0&&old_md5[1]!=0&&old_md5[2]!=0&&old_md5[3]!=0&&
     old_md5[4]!=0&&old_md5[5]!=0&&old_md5[6]!=0&&old_md5[7]!=0)
    &&
    time(NULL)-biggest_last_access_time>config->check_time_interval*2)
    //if files not modify recently, then return old md5
   {
    memcpy(md,old_md5,sizeof(old_md5));
    memcpy(config->file_items,old_file_items,sizeof(old_file_items));
    return 1;
   }
 i=0;
 for(;i<config->file_item_count;i++)
    {
     size_t file_length=0;
     char* content=read_file(config->file_items[i].filename,&file_length);
     if(content==NULL)
        return -3;
     if(strlen(config->file_items[i].begin_string[0])==0)//get entire file md5
       {
        md5(content,content+file_length,config->file_items[i].md5);
       }
     else //find all begin=>end then caculate md5
       {
        char* content2=(char*)malloc(file_length);
        size_t content2_length=0;
        int k=0;
	char* p=content;
	for(;k<FILE_MAX_SECTION;k++)
	   {
	    if(strlen(config->file_items[i].begin_string[k])==0)
	       break;
	    p=strstr(p,config->file_items[i].begin_string[k]);
	    if(p==NULL)
	       break;
	    char* p2=NULL;
	    if(strlen(config->file_items[i].end_string[k])>0)
	      {
	       p2=strstr(p,config->file_items[i].end_string[k]);
	       if(p2!=NULL)
	          p2=p2+strlen(config->file_items[i].end_string[k]);
	       else
	          p2=content+file_length;
	      }
	    memcpy(content2+content2_length,p,p2-p);
	    content2_length+=p2-p;
	    p=p2;
	    if(p>content+file_length)
	       break;
	   }//end for k
	content2[content2_length]=0;
	md5(content2,content2+content2_length,config->file_items[i].md5);
	//printf("content2:[\n%s\n]\n",content2);
	free(content2);
       }
     free(content);
    }//end for i
 char buffer[1024];
 char* p=buffer;
 memset(buffer,0,sizeof(buffer));
 i=0;
 for(;i<config->file_item_count;i++)
    {
     char* p2=md52string(config->file_items[i].md5,p);
     printf("{%s}\n",p);
     p=p2;
    }
 md5(buffer,p,md);
 memcpy(old_md5,md,sizeof(md));
 memcpy(old_file_items,config->file_items,sizeof(config->file_items));
 return 1;
}
//-------------------------------------------------------------------------------------------------

void do_aes(char* in,char* out,char* key)
{
 char aes_key[16];
 memset(aes_key,0,16);
 strncpy(aes_key,key,16);
 AES_KEY enc_key;
 AES_set_encrypt_key((unsigned char*)aes_key,sizeof(aes_key)*8,&enc_key);

 unsigned char ivec[AES_BLOCK_SIZE];
 memset(ivec,0,sizeof(ivec));
 char* new_in=NULL;
 char* new_out=NULL;
 size_t new_length=0;
 
 size_t length=strlen(in);
 new_length=length;
 if(new_length%AES_BLOCK_SIZE!=0)
    new_length=((length/AES_BLOCK_SIZE)+1)*AES_BLOCK_SIZE;
 new_in=calloc(new_length+1,sizeof(char));
 memcpy(new_in,in,length);
 new_out=calloc(new_length+1,sizeof(char));
 
 AES_cbc_encrypt((unsigned char *)new_in,(unsigned char *)new_out, 
                 new_length,&enc_key,ivec,AES_ENCRYPT);
 int i=0;
 for(;i<new_length;i++)
    {
     //printf("%02X ",new_out[i]&0xFF);
     out=out+sprintf(out,"%02X",new_out[i]&0xFF);
    }
 free(new_in);
 free(new_out); 
}
//-------------------------------------------------------------------------------------------------
