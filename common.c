#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/un.h> 
#include <sys/sysinfo.h>
#include <errno.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "common.h"
#include "md5.h"
#include "config.h"
#include "base64.h"

#ifdef BUILD_MIPS
#include "nbos_version.h"
#include "nbos_hal_api.h"
#endif

//-------------------------------------------------------------------------------------------------
static unsigned char old_md5[16];
static time_t old_md5_timestamp;
static FileItem old_file_items[FILE_MAX_NUMBER];
const unsigned char AES_IV_PADDING_CHAR='0';
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
 while(*s!=0&&
       (*s==' '||*s=='\t'||*s=='\n'||*s=='\r'||*s=='\''||*s=='"')
      )
       s++;
 while(e>s&&
       (*e==' '||*e=='\t'||*e=='\n'||*e=='\r'||*e=='\''||*e=='"')
      )
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
 mac[0]=0xb8;
 mac[1]=0x09;
 mac[2]=0x8a;
 mac[3]=0xc9;
 mac[4]=0x92;
 mac[5]=0xc1;
 return 1;
}

int get_mac_str(char * strmac)
{
#ifdef BUILD_MIPS
	if(nbos_read_mac(strmac) < 0) {
		printf("failed to get mac, errno:%d\n",errno);
		return -1;
	}
#else
	unsigned char mac[6];
	if(get_mac(mac)<0)
	{
		printf("failed to get mac, errno:%d\n",errno);
		return -1;
	}
	mac2string(mac, strmac);
#endif
	return 0;
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
    time(NULL)-biggest_last_access_time>config->check_time_interval*2
    &&
    (old_md5_timestamp>1000000&&(time(NULL)-old_md5_timestamp)<FILES_MD5_EXPIRE_TIME)
   )
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
     //printf("{%s}\n",p);
     p=p2;
    }
 md5(buffer,p,md);
 memcpy(old_md5,md,sizeof(old_md5));
 memcpy(old_file_items,config->file_items,sizeof(config->file_items));
 old_md5_timestamp=time(NULL);
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
 out_length=m;
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

int send_message_to_unix_socket(char* socket_name,char* message,size_t length)
{
 int sockfd;
 struct sockaddr_un sa;
 int ret;
 if((sockfd=socket(AF_UNIX,SOCK_DGRAM,0))==-1)
   {
    printf("%lu\tfailed to create unix socket %d\n",time(NULL),errno);
    return -1;
   }
 memset (&sa, 0, sizeof(struct sockaddr_un));
 sa.sun_family = AF_UNIX;
 snprintf(sa.sun_path,sizeof(sa.sun_path),socket_name);
 ret=sendto(sockfd,message,length,0,(struct sockaddr *)&sa,sizeof(sa));
 if(ret<0)
    printf("%lu\tfailed to sendto %s\n",time(NULL),socket_name);
 close(sockfd);
 return ret;
}
//-------------------------------------------------------------------------------------------------

#ifdef BUILD_MIPS
static int get_system_version(const char *file, const char *defval, char *strver)
{
	FILE *pfile = NULL;
	char strbuff[64];
	char *chtemp = NULL, *chptr = NULL;
	int len;

	pfile = fopen(file, "r");
	if(pfile == NULL) {
		sprintf(strver, "%s", defval);
		return -1;
	}
	memset(strbuff, 0, sizeof(strbuff));
	len = fread(strbuff, 1, sizeof(strbuff), pfile);
	if(len < 0) {
		goto ERR_FAIL;
	}
	chtemp = strchr(strbuff, ':');
	if(chtemp == NULL) {
		goto ERR_FAIL;
	}
	while(*chtemp == ':' || *chtemp == ' ')
		chtemp++;
	chptr = chtemp + strlen(chtemp) - 1;
	while(*chptr == '\n' || *chptr == ' ') {
		*chptr = '\0';
		chptr--;
	}
	fclose(pfile);
	strncpy(strver, chtemp, strlen(chtemp));
	return 0;

ERR_FAIL:
	sprintf(strver, "%s", defval);
	fclose(pfile);
	return -1;
}

static int get_imgfile_version(const char *file, const char *defval, char *strver)
{
    nb_image_t headimage;
    FILE *pfile = NULL;

    if(file == NULL)
    	goto ERR_FAIL;

    pfile = fopen(file, "r");
    if (pfile == NULL)
    	goto ERR_FAIL;
    if(fread(&headimage, sizeof(nb_image_t), 1, pfile) <=0 )
    	goto ERR_FAIL;
    fclose(pfile);
    strncpy(strver, headimage.nbVersion, strlen(headimage.nbVersion));
    return 0;

ERR_FAIL:
	sprintf(strver, "%s", defval);
	if(pfile != NULL)
		fclose(pfile);
	return -1;
}

static int get_proc_file_str(const char *file, char *strval) {
	char buff[32];
	int ret;
	FILE *pfile = NULL;

	if(file == NULL)
		return -1;

	memset(buff, 0, sizeof(buff));
	pfile = fopen(file, "r");
	if(pfile == NULL) {
		perror("open file failed");
		return -1;
	}
	ret = fread(buff, sizeof(buff), 1, pfile);
	if(ret < 0) {
		fclose(pfile);
		return -1;
	}
	strncpy(strval, buff, strlen(buff));
	fclose(pfile);
	return 0;
}

int get_net_ip(char *eth, char *ipaddr)
{
	int sock_fd;
	struct  sockaddr_in my_addr;
	struct ifreq ifr;

	if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, eth, strlen(eth));

	if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
		printf("No Such Device %s/n",eth);
		return -1;
	}

	memcpy(&my_addr, &ifr.ifr_addr, sizeof(my_addr));
	strcpy(ipaddr, inet_ntoa(my_addr.sin_addr));
	close(sock_fd);
	return 0;
}
#endif

#define D_CURVERSION_FILE			"/tmp/curversion"
#define D_BACKUPVERSION_FILE		"/tmp/backupversion"
#define D_FACTORYVERSION_FILE		"/usr/system/backup/nbos.stable"
#define D_WLAN_CLIENT_COUNT_FILE	"/proc/sys/dev/wifi0/nb_sta_assoc"
#define D_UPLINKTYPE_FILE			"/etc/uplinktype"

void get_wtp_ip(void* config_, char* ipstr)
{
#ifdef BUILD_MIPS
	char buff[64] = {0};
	char netstr[16] = {0};
	char *default_ip = "0.0.0.0";
	if(get_proc_file_str(D_UPLINKTYPE_FILE, buff) < 0) {
		strcpy(ipstr, default_ip);
		return ;
	}
	if(strncmp(buff, "UPLINK_DHCP_DISCOVER", strlen("UPLINK_DHCP_DISCOVER")) == 0)
		strcpy(netstr, "eth0");
	else if(strncmp(buff, "UPLINK_PPPOE_DISCOVER", strlen("UPLINK_PPPOE_DISCOVER")) == 0)
		strcpy(netstr, "ppp0");
	else if(strncmp(buff, "UPLINK_STATION", strlen("UPLINK_STATION")) == 0)
		strcpy(netstr, "ath0");
	else
		strcpy(ipstr, default_ip);
	if(strlen(netstr) > 0)
		get_net_ip(netstr, ipstr);
#else
	sprintf(ipstr, "%s","192.168.0.2");
#endif
}

void get_primary_ver(void* config_,char* string)
{
#ifdef BUILD_MIPS
	get_system_version(D_CURVERSION_FILE, "NBOS-1.0.0.0", string);
#else
	sprintf(string,"%s","NB11");
#endif
}
//-------------------------------------------------------------------------------------------------

void get_factory_ver(void* config_,char* string)
{
#ifdef BUILD_MIPS
	get_imgfile_version(D_FACTORYVERSION_FILE, "NBOS-1.0.0.0", string);
#else
	sprintf(string,"%s","NB12");
#endif
}
//-------------------------------------------------------------------------------------------------

void get_backup_ver(void* config_,char* string)
{
#ifdef BUILD_MIPS
	get_system_version(D_BACKUPVERSION_FILE, "NBBK-1.0.0.0", string);
#else
	sprintf(string,"%s","NB13");
#endif
}
//-------------------------------------------------------------------------------------------------

void get_uplinktype(void* config_,char* string)
{
#ifdef BUILD_MIPS
	char buff[64] = {0};
	if(get_proc_file_str(D_UPLINKTYPE_FILE, buff) < 0) {
		strcpy(string, "UNKNOWN");
		return ;
	}
	if(strncmp(buff, "UPLINK_DHCP_DISCOVER", strlen("UPLINK_DHCP_DISCOVER")) == 0)
		strcpy(string, "DHCP");
	else if(strncmp(buff, "UPLINK_PPPOE_DISCOVER", strlen("UPLINK_PPPOE_DISCOVER")) == 0)
		strcpy(string, "PPPOE");
	else if(strncmp(buff, "UPLINK_STATION", strlen("UPLINK_STATION")) == 0)
		strcpy(string, "STATION");
	else
		strcpy(string, "UNKNOWN");
#else
	sprintf(string,"%s","DHCP");
#endif
}
//-------------------------------------------------------------------------------------------------

unsigned int get_ternum(void* config_)
{
#ifdef BUILD_MIPS
	char buff[32] = {0};
	get_proc_file_str(D_WLAN_CLIENT_COUNT_FILE, buff);
	return atoi(buff);
#else
	return 5;
#endif
}

void get_uptime(void *config_, char *strtime) {
	struct  sysinfo info;
	sysinfo(&info);
	sprintf(strtime, "%ld", info.uptime);
}
//-------------------------------------------------------------------------------------------------
