#include "mycurl.h"
//-------------------------------------------------------------------------------------------------
static unsigned int received_index=0;
//-------------------------------------------------------------------------------------------------

int write_function(void* ptr,size_t size,size_t nmemb,void* stream)
{
 size_t irsize=size*nmemb;
 char* s=(char*)stream;
 if(ptr!=NULL)
   {
    memcpy(&(s[received_index]),ptr,irsize);
    received_index+=irsize;
    s[received_index]=0;
   }
 return irsize;
}
//-------------------------------------------------------------------------------------------------

int do_wget(Config* config,char* url,char* post_data,char* received)
{
 received_index=0;
 CURL *curl_handle=NULL;
 CURLcode rv=0;
 curl_handle=curl_easy_init();
 if(curl_handle==NULL)
    return -1;
 curl_easy_setopt(curl_handle,CURLOPT_URL,url);
 curl_easy_setopt(curl_handle,CURLOPT_TIMEOUT,config->request_timeout_seconds);
 curl_easy_setopt(curl_handle,CURLOPT_CONNECTTIMEOUT,config->connection_timeout_seconds);

 //if(post_data!=NULL)
   {
    //curl_easy_setopt(curl_handle,CURLOPT_POSTFIELDSIZE,strlen(post_data));
    //curl_easy_setopt(curl_handle,CURLOPT_POSTFIELDS,post_data);
    //curl_easy_setopt(curl_handle,CURLOPT_POST,1);
   }
 if(received!=NULL)
   {
    curl_easy_setopt(curl_handle,CURLOPT_WRITEDATA,(void *)received);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,write_function);
   }
 rv=curl_easy_perform(curl_handle);
 if(rv!=CURLE_OK)
   {
    curl_easy_cleanup(curl_handle);
    return -2;
   }
 int rc=200;
 curl_easy_getinfo(curl_handle,CURLINFO_RESPONSE_CODE,&rc);
 curl_easy_cleanup(curl_handle);
 return rc;
}
//-------------------------------------------------------------------------------------------------
