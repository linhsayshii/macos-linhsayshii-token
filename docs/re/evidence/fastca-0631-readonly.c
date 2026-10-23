#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libopensc/opensc.h"
static int read_file(sc_card_t *card,unsigned fid,const char *output) {
 if(fid!=0x6f01 && !(fid>=0x2000&&fid<0x4000))return -1;
 char text[32];snprintf(text,sizeof text,"3f002003%04x",fid);sc_path_t path;sc_format_path(text,&path);sc_file_t *file=NULL;
 int rv=sc_select_file(card,&path,&file);if(rv<0||!file)return rv<0?rv:-1;
 size_t n=file->size;sc_file_free(file);if(!n||n>65536)return -1;
 unsigned char *bytes=malloc(n);if(!bytes)return -1;unsigned long flags=0;rv=sc_read_binary(card,0,bytes,n,&flags);
 if(rv==(int)n){FILE *f=fopen(output,"wb");if(!f){free(bytes);return -1;}if(fwrite(bytes,1,n,f)!=n){fclose(f);free(bytes);return -1;}fclose(f);printf("READ fid=%04X bytes=%zu\n",fid,n);}
 free(bytes);return rv==(int)n?0:-1;
}
int main(int argc,char **argv){
 if(argc!=3)return 2;unsetenv("OPENSC_DEBUG_FILE");setenv("OPENSC_DEBUG","0",1);
 sc_context_t *ctx=NULL;sc_card_t *card=NULL;sc_context_param_t p={0};p.app_name="TokenSignerFastCAReadOnly";
 int rv=sc_context_create(&ctx,&p),result=1,locked=0;if(rv<0)return 3;ctx->debug=0;
 sc_reader_t *reader=sc_ctx_get_reader_by_name(ctx,argv[1]);if(!reader)goto done;
 if(sc_connect_card(reader,&card)<0)goto done;
 const unsigned char expected[]={0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,0x05,0x10,0x06,0x31,0x71,0xdf,0,0,0x69,0,0,0x4d};
 if(card->atr.len!=sizeof expected||memcmp(card->atr.value,expected,sizeof expected))goto done;
 printf("driver=%s ATR=",card->driver->short_name);for(size_t i=0;i<card->atr.len;i++)printf("%02x",card->atr.value[i]);puts("");
 if(sc_lock(card)<0)goto done;locked=1;char path[2048];snprintf(path,sizeof path,"%s/catalog.bin",argv[2]);if(read_file(card,0x6f01,path)<0)goto done;
 FILE *f=fopen(path,"rb");if(!f)goto done;unsigned char catalog[1500];size_t n=fread(catalog,1,sizeof catalog,f);fclose(f);if(n!=sizeof catalog)goto done;
 for(unsigned i=0;i<1500;i+=30){unsigned fid=catalog[i]|(catalog[i+1]<<8);if(!fid||fid==0xffff)continue;char directory[11]={0},name[13]={0};memcpy(directory,catalog+i+2,10);memcpy(name,catalog+i+12,12);
  if((!strcmp(directory,"pkcs11")&&(!strncmp(name,"cert",4)||!strncmp(name,"prvk",4)))||(!directory[0]&&!strcmp(name,"cardid"))){snprintf(path,sizeof path,"%s/%04x.bin",argv[2],fid);if(read_file(card,fid,path)<0)goto done;}
 }
 result=0;puts("PASS metadata read only; no authentication or signing");
done:if(card){if(locked)sc_unlock(card);sc_disconnect_card(card);}sc_release_context(ctx);return result;
}
