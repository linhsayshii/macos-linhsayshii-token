// Research only: OpenSC ARM64 transport + bounded public ESPK metadata reads.
// No user PIN/login, private key EF reads, card writes, or signature operation.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
#include "libopensc/opensc.h"
static const unsigned char expected_atr[23]={0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,0x05,0x10,0x11,0x39,0x71,0xdf,0,0,0x51,0,0,0x6a};
static void hash(const unsigned char *p,size_t n,char out[65]) {unsigned char b[32];CC_SHA256(p,(CC_LONG)n,b);for(int i=0;i<32;i++)sprintf(out+2*i,"%02x",b[i]);out[64]=0;}
static int read_metadata(sc_card_t *c,unsigned short fid,unsigned char **out,size_t *size) {
 if(!((fid>=0x2000&&fid<0x4000)||fid==0x6f01))return -20001;
 char name[16];snprintf(name,sizeof(name),"3f002003%04x",fid);
 sc_path_t p;sc_format_path(name,&p);sc_file_t *f=NULL;int r=sc_select_file(c,&p,&f);
 printf("select.%04x=%d\n",fid,r);if(r<0||!f){if(f)sc_file_free(f);return r<0?r:-20002;}
 *size=f->size;sc_file_free(f);if(!*size||*size>65536)return -20003;
 *out=malloc(*size);if(!*out)return -20004;unsigned long flags=0;
 r=sc_read_binary(c,0,*out,*size,&flags);printf("read.%04x=%d; expected=%zu\n",fid,r,*size);
 if(r<0||(size_t)r!=*size){free(*out);*out=NULL;return r<0?r:-20005;}return 0;
}
static int save(const char *dir,const char *name,const unsigned char *b,size_t n) {
 char path[1024];int len=snprintf(path,sizeof(path),"%s/%s",dir,name);if(len<0||(size_t)len>=sizeof(path))return -1;
 FILE *f=fopen(path,"wb");if(!f)return -1;size_t w=fwrite(b,1,n,f);fclose(f);chmod(path,0600);return w==n?0:-1;
}
static int field(char *out,const unsigned char *p,size_t n) {
 size_t i=0;for(;i<n&&p[i];i++){if(p[i]<0x20||p[i]>0x7e||p[i]=='/'||p[i]=='\\')return 0;out[i]=p[i];}out[i]=0;return 1;
}
int main(int argc,char **argv) {
 if(argc!=2)return 2;setvbuf(stdout,NULL,_IONBF,0);
 unsetenv("OPENSC_DEBUG_FILE");unsetenv("OPENSC_CONF");setenv("OPENSC_DEBUG","0",1);
 printf("process=arm64; opensc=%s\n",sc_get_version());if(strcmp(sc_get_version(),"0.27.1"))return 3;
 sc_context_t *ctx=NULL;sc_card_t *card=NULL;sc_context_param_t p={0};p.app_name="TokenSignerEFYReadOnly";p.flags=SC_CTX_FLAG_DISABLE_POPUPS;p.debug=0;
 int r=sc_context_create(&ctx,&p);printf("context=%d\n",r);if(r<0)return 4;ctx->debug=0;int result=5,locked=0;
 sc_reader_t *target=NULL;unsigned n=sc_ctx_get_reader_count(ctx);printf("reader-count=%u\n",n);
 for(unsigned i=0;i<n;i++){sc_reader_t *reader=sc_ctx_get_reader(ctx,i);if(!reader)continue;int status=sc_detect_card_presence(reader);
  if(status>=0&&reader->atr.len==sizeof(expected_atr)&&!memcmp(reader->atr.value,expected_atr,sizeof(expected_atr))){if(target){fputs("ambiguous EFY ATR\n",stderr);goto done;}target=reader;}
 }
 if(!target){fputs("expected EFY ATR not found; no card connected\n",stderr);goto done;}
 printf("selected-reader=%s; ATR=",target->name);for(size_t i=0;i<sizeof(expected_atr);i++)printf("%02x",expected_atr[i]);putchar('\n');
 r=sc_connect_card(target,&card);printf("connect=%d\n",r);if(r<0)goto done;
 if(card->atr.len!=sizeof(expected_atr)||memcmp(card->atr.value,expected_atr,sizeof(expected_atr))||!card->driver||strcmp(card->driver->short_name,"epass2003")){fputs("card profile/driver mismatch\n",stderr);goto done;}
 printf("driver=%s\n",card->driver->short_name);r=sc_lock(card);printf("lock=%d\n",r);if(r<0)goto done;locked=1;
 unsigned char *catalog=NULL;size_t size=0;r=read_metadata(card,0x6f01,&catalog,&size);if(r<0)goto done;
 char hs[65];hash(catalog,size,hs);printf("catalog.bytes=%zu; SHA256=%s\n",size,hs);
 if(size!=1500){free(catalog);fputs("unknown catalog format\n",stderr);goto done;}
 if(save(argv[1],"catalog.bin",catalog,size)){free(catalog);goto done;}
 int count=0;
 for(size_t start=0;start<size;start+=30) {
  unsigned short fid=catalog[start]|((unsigned short)catalog[start+1]<<8);if(!fid||fid==0xffff)continue;
  char dir[11]={0},name[13]={0};if(!field(dir,catalog+start+2,10)||!field(name,catalog+start+12,12)){free(catalog);goto done;}
  printf("catalog.entry fid=%04x; logical=%s/%s\n",fid,dir,name);count++;
  int wanted=(!dir[0]&&!strcmp(name,"cardid"))||(!strcmp(dir,"pkcs11")&&(!strncmp(name,"cert",4)||!strncmp(name,"prvk",4)||!strncmp(name,"pubk",4)));
  if(!wanted)continue;
  unsigned char *data=NULL;size_t length=0;r=read_metadata(card,fid,&data,&length);if(r<0){printf("metadata-unreadable.%04x=%d\n",fid,r);continue;}
  char hs2[65],filename[32];hash(data,length,hs2);snprintf(filename,sizeof(filename),"%04x.bin",fid);
  printf("metadata.%04x bytes=%zu; SHA256=%s\n",fid,length,hs2);if(save(argv[1],filename,data,length)){free(data);free(catalog);goto done;}free(data);
 }
 free(catalog);printf("catalog.entries=%d\n",count);result=0;
done:
 if(card){if(locked)sc_unlock(card);sc_disconnect_card(card);}
 sc_release_context(ctx);return result;
}
