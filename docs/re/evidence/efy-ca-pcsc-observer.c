// Diagnostic interposer: forwards original PC/SC parameters/results unchanged.
#include <stdio.h>
#include <PCSC/winscard.h>
static int32_t ctx(uint32_t s,const void *a,const void *b,SCARDCONTEXT *c) {
 int32_t r=SCardEstablishContext(s,a,b,c);fprintf(stderr,"[efy-observe] context rv=0x%x\n",r);return r;
}
static int32_t state(SCARDCONTEXT c,uint32_t t,LPSCARD_READERSTATE_A st,uint32_t n) {
 for(uint32_t i=0;i<n&&i<32;i++)fprintf(stderr,"[efy-observe] status.request reader=%s; timeout=%u\n",st[i].szReader?st[i].szReader:"(null)",t);
 int32_t r=SCardGetStatusChange(c,t,st,n);fprintf(stderr,"[efy-observe] status.rv=0x%x\n",r);return r;
}
static int32_t connect_card(SCARDCONTEXT c,const char *name,uint32_t share,uint32_t prot,SCARDHANDLE *h,uint32_t *actual) {
 int32_t r=SCardConnect(c,name,share,prot,h,actual);fprintf(stderr,"[efy-observe] connect reader=%s; rv=0x%x\n",name?name:"(null)",r);return r;
}
static int32_t tx(SCARDHANDLE h,LPCSCARD_IO_REQUEST p,const unsigned char *b,uint32_t n,LPSCARD_IO_REQUEST q,unsigned char *out,uint32_t *len) {
 int32_t r=SCardTransmit(h,p,b,n,q,out,len);fprintf(stderr,"[efy-observe] transmit len=%u; header=",n);for(uint32_t i=0;i<n&&i<5;i++)fprintf(stderr,"%02x",b[i]);fprintf(stderr,"; rv=0x%x",r);if(!r&&len&&*len>=2)fprintf(stderr,"; sw=%02x%02x",out[*len-2],out[*len-1]);fputc('\n',stderr);return r;
}
#define INTERPOSE(name,replacement,original) __attribute__((used)) static struct{const void *a,*b;} name __attribute__((section("__DATA,__interpose")))={(const void*)replacement,(const void*)original}
INTERPOSE(i_ctx,ctx,SCardEstablishContext);
INTERPOSE(i_state,state,SCardGetStatusChange);
INTERPOSE(i_connect,connect_card,SCardConnect);
INTERPOSE(i_tx,tx,SCardTransmit);
#include <errno.h>
#include <string.h>
static FILE *observe_popen(const char *cmd,const char *mode) {
 FILE *p=popen(cmd,mode);fprintf(stderr,"[efy-observe] popen=%s; opened=%d\n",cmd?cmd:"(null)",p!=NULL);return p;
}
extern int old_stat(const char *path,void *buf) __asm("_stat");
static int observe_stat(const char *path,void *buf) {
 int r=old_stat(path,buf);int e=errno;if(path&&!strcmp(path,"/var/run/pcscd"))fprintf(stderr,"[efy-observe] stat=%s; rv=%d; errno=%d\n",path,r,e);errno=e;return r;
}
INTERPOSE(i_popen,observe_popen,popen);
INTERPOSE(i_stat,observe_stat,old_stat);
