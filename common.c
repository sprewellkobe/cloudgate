#include "common.h"
#include "md5.h"
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

void md5(char* string,unsigned char *m)
{
 MD5_CTX md5;
 MD5Init(&md5);
 MD5Update(&md5,(unsigned char*)string,strlen(string));
 MD5Final(&md5,m);
}
//-------------------------------------------------------------------------------------------------

void md52string(unsigned char* m,char* string)
{
 int i=0;
 for(;i<16;i++)
     string=string+sprintf(string,"%02x",m[i]);
}
//-------------------------------------------------------------------------------------------------

int get_mac(unsigned char* mac)
{
 return 1;
}
//-------------------------------------------------------------------------------------------------
