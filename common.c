#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "md5.h"
#include "config.h"
#include "base64.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
//-------------------------------------------------------------------------------------------------
static unsigned char old_md5[16];
static FileItem old_file_items[FILE_MAX_NUMBER];
const unsigned char AES_IV_PADDING_CHAR='X';
const char* CIPHER_NAME="aes-128-cbc";
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
    #ifdef MYDEBUG
    printf("cache hitted\n");
    #endif
    memcpy(md,old_md5,sizeof(old_md5));
    memcpy(config->file_items,old_file_items,sizeof(old_file_items));
    return 1;
   }
 #ifdef MYDEBUG
 printf("real caculate\n");
 #endif
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

void write_to_hex(char* in,size_t in_length,char* out)
{
 int i=0;
 for(;i<in_length;i++) out=out+sprintf(out,"%02X",in[i]&0xFF); 
}
//-------------------------------------------------------------------------------------------------

void read_from_hex(char* in,char* out,size_t* out_length)
{
 int p=0;
 int i=0;
 while(in[p]!=0)
      {
       unsigned int t=0;
       sscanf(in+p,"%02X",&t);
       out[i++]=(unsigned char)t;
       p+=2;
      }//end while
 out[i]=0;
 *out_length=i;
}
//-------------------------------------------------------------------------------------------------

int do_aes_encrypt(char* in,char* out,char* key_)
{
 unsigned char iv[AES_BLOCK_SIZE];
 memset(iv,AES_IV_PADDING_CHAR,sizeof(iv));
 size_t in_length=strlen(in);
 size_t new_out_length=in_length+AES_BLOCK_SIZE;
 char* new_out=calloc(new_out_length+1,1);
 OpenSSL_add_all_algorithms();
 const EVP_CIPHER* cipher_type=EVP_get_cipherbyname(CIPHER_NAME);
 if(cipher_type==NULL)
    return -1;
 int key_length=EVP_CIPHER_key_length(cipher_type);
 unsigned char* key=NULL;
 if(key_length>strlen(key_)) 
   {
    key=calloc(key_length,1);
    memcpy(key,key_,strlen(key_));
   }
 else
    key=(unsigned char*)key_;
 EVP_CIPHER_CTX cipher_ctx;
 EVP_EncryptInit(&cipher_ctx,cipher_type,NULL,NULL);
 if(strlen(key_)>key_length)
    EVP_CIPHER_CTX_set_key_length(&cipher_ctx,strlen(key_));
 EVP_EncryptInit_ex(&cipher_ctx,NULL,NULL,key,iv);
 int m;
 EVP_EncryptUpdate(&cipher_ctx,(unsigned char*)new_out,&m,(unsigned char*)in,in_length);
 new_out_length=m;
 if(EVP_EncryptFinal(&cipher_ctx,(unsigned char *)new_out+m,&m))
   {
    new_out_length+=m;
    new_out[new_out_length]=0;
   }
 if((char*)key!=key_) free(key);
 EVP_CIPHER_CTX_cleanup(&cipher_ctx);
 write_to_hex(new_out,new_out_length,out);
 free(new_out);
 return 1;
}
//-------------------------------------------------------------------------------------------------

int do_aes_decrypt(char* in_,char* out,char* key_)
{
 unsigned char iv[AES_BLOCK_SIZE];
 memset(iv,AES_IV_PADDING_CHAR,sizeof(iv));
 size_t in_length=0;
 char* in=calloc((strlen(in_)+1)/2+1,1);
 read_from_hex(in_,in,&in_length);
 size_t out_length=0;

 OpenSSL_add_all_algorithms();
 const EVP_CIPHER* cipher_type=EVP_get_cipherbyname(CIPHER_NAME);
 if(cipher_type==NULL)
    return -1;
 int key_length=EVP_CIPHER_key_length(cipher_type);
 unsigned char* key=NULL;
 if(key_length>strlen(key_))
   {
    key=calloc(key_length,1);
    memcpy(key,key_,strlen(key_));
   }
 else
    key=(unsigned char*)key_;
 EVP_CIPHER_CTX cipher_ctx;
 EVP_DecryptInit(&cipher_ctx,cipher_type,NULL,NULL);
 if(strlen(key_)>key_length)
    EVP_CIPHER_CTX_set_key_length(&cipher_ctx,strlen(key_));
 EVP_DecryptInit_ex(&cipher_ctx,NULL,NULL,key,iv);
 int m=0;
 EVP_DecryptUpdate(&cipher_ctx,(unsigned char*)out,&m,(unsigned char *)in,in_length);
 if(EVP_DecryptFinal(&cipher_ctx,(unsigned char *)out+m,&m)) 
   {
    out_length+=m;
    out[out_length]=0;
   }
 if((char*)key!=key_) free(key);
 EVP_CIPHER_CTX_cleanup(&cipher_ctx);
 free(in);
 return 1;
}
//-------------------------------------------------------------------------------------------------
