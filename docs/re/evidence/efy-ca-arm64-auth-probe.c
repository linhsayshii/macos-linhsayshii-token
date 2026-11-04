// Sample-specific EFY research harness. One user authentication, never a signature.
// --preflight never reads a PIN or sends a user-authentication APDU.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#include "libopensc/opensc.h"

static const unsigned char atr[]={0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0,0x66,0x46,0x53,0x05,0x10,0x11,0x39,0x71,0xdf,0,0,0x51,0,0,0x6a};
static const unsigned char cert_hash[]={0x82,0xd0,0x25,0x09,0x71,0x5e,0x72,0x73,0x63,0x9d,0xb3,0x7d,0x62,0xc3,0x64,0xea,0xf5,0x4c,0xfb,0x15,0xff,0x9f,0xdf,0x79,0xf1,0x0c,0x60,0x9e,0xa6,0x65,0x15,0xc9};
static void wipe(void *v,size_t n){volatile unsigned char *p=v;while(n--)*p++=0;}
static uint32_t le32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int certificate_matches(sc_card_t *card){
 sc_path_t path;sc_file_t *f=NULL;sc_format_path("3f00200324c0",&path);
 int rv=sc_select_file(card,&path,&f);if(rv<0||!f){if(f)sc_file_free(f);return 0;}
 size_t size=f->size;sc_file_free(f);if(size<8||size>16384)return 0;
 unsigned char data[16384],digest[32];unsigned long flags=0;
 rv=sc_read_binary(card,0,data,size,&flags);if(rv!=(int)size)return 0;
 int matched=0,seen=0;
 for(size_t pos=0;pos<size;){
  if(size-pos<8)return 0;uint32_t type=le32(data+pos),n=le32(data+pos+4);pos+=8;
  if(n>size-pos)return 0;
  if(type==0x11){if(seen++)return 0;CC_SHA256(data+pos,n,digest);matched=!memcmp(digest,cert_hash,sizeof digest);}
  pos+=n;
 }
 return matched;
}
int main(int argc,char **argv){
 int preflight=argc==2&&!strcmp(argv[1],"--preflight");if(argc!=1&&!preflight)return 2;
 struct rlimit core={0,0};setrlimit(RLIMIT_CORE,&core);setvbuf(stdout,NULL,_IONBF,0);
 unsetenv("OPENSC_DEBUG_FILE");unsetenv("OPENSC_CONF");setenv("OPENSC_DEBUG","0",1);
 if(strcmp(sc_get_version(),"0.27.1")){puts("STOP runtime version");return 3;}
 sc_context_t *ctx=NULL;sc_card_t *card=NULL;sc_context_param_t params={0};
 params.app_name="TokenSignerEFYAuthResearch";params.debug=0;params.flags=SC_CTX_FLAG_DISABLE_POPUPS;
 int rv=sc_context_create(&ctx,&params);if(rv<0){printf("STOP context rv=%d\n",rv);return 4;}ctx->debug=0;
 int result=1,locked=0,attempted=0;
 unsigned char pin[129]={0},key[24]={0},challenge[8]={0},crypt[8]={0},iv[8]={0};
 sc_reader_t *target=NULL;
 for(unsigned i=0;i<sc_ctx_get_reader_count(ctx);i++){
  sc_reader_t *r=sc_ctx_get_reader(ctx,i);if(!r)continue;
  if(sc_detect_card_presence(r)>=0&&r->atr.len==sizeof atr&&!memcmp(r->atr.value,atr,sizeof atr)){
   if(target){puts("STOP ambiguous EFY token");goto done;}target=r;
  }
 }
 if(!target){puts("STOP expected EFY token missing");goto done;}
 rv=sc_connect_card(target,&card);if(rv<0){printf("STOP connect rv=%d\n",rv);goto done;}
 if(card->atr.len!=sizeof atr||memcmp(card->atr.value,atr,sizeof atr)||!card->driver||strcmp(card->driver->short_name,"epass2003")){puts("STOP token profile");goto done;}
 rv=sc_lock(card);if(rv<0){printf("STOP lock rv=%d\n",rv);goto done;}locked=1;
 if(!certificate_matches(card)){puts("STOP EFY certificate mismatch");goto done;}
 sc_path_t df;sc_format_path("3f002003",&df);rv=sc_select_file(card,&df,NULL);
 if(rv<0){printf("STOP DF select rv=%d\n",rv);goto done;}
 puts("PREFLIGHT PASS arm64; OpenSC 0.27.1; exact EFY ATR and certificate");
 if(preflight){result=0;goto done;}
 if(!fgets((char *)pin,sizeof pin,stdin)){puts("CANCEL no PIN");goto done;}
 size_t n=strlen((char *)pin);if(n&&pin[n-1]=='\n')pin[--n]=0;
 else {puts("STOP incomplete PIN input");goto done;}
 if(n<1||n>64){puts("STOP PIN input length");goto done;}
 for(size_t i=0;i<n;i++)if(pin[i]<0x20||pin[i]>0x7e){puts("STOP PIN encoding");goto done;}
 // EFY vendor raw-PIN transform at 0xa9bdb: SHA1(bytes) || BE32(byte count).
 CC_SHA1(pin,(CC_LONG)n,key);key[20]=(n>>24)&255;key[21]=(n>>16)&255;key[22]=(n>>8)&255;key[23]=n&255;
 wipe(pin,sizeof pin);
 rv=sc_get_challenge(card,challenge,sizeof challenge);
 if(rv<0){printf("STOP challenge rv=%d\n",rv);goto done;}
 // ePass2003 challenge route, also present at EFY vendor 0x963ca/0x8ee7a.
 size_t out=0;CCCryptorStatus cs=CCCrypt(kCCEncrypt,kCCAlgorithm3DES,0,key,sizeof key,iv,challenge,sizeof challenge,crypt,sizeof crypt,&out);
 wipe(key,sizeof key);wipe(challenge,sizeof challenge);
 if(cs!=kCCSuccess||out!=sizeof crypt){puts("STOP cryptogram generation");goto done;}
 sc_apdu_t apdu;sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x82,1,0x81);
 apdu.data=crypt;apdu.datalen=apdu.lc=sizeof crypt;
 apdu.flags|=SC_APDU_FLAGS_NO_RETRY_WL|SC_APDU_FLAGS_NO_GET_RESP;
 attempted=1;rv=sc_transmit_apdu(card,&apdu);wipe(crypt,sizeof crypt);
 if(rv<0){printf("AUTH transport rv=%d; outcome uncertain; no retry\n",rv);goto done;}
 printf("AUTH SW=%02X%02X; no retry\n",apdu.sw1,apdu.sw2);
 if(apdu.sw1==0x90&&apdu.sw2==0){puts("PASS native ARM64 EFY PIN authentication");result=0;}
 else puts("STOP authentication rejected; no fallback or retry");
done:
 wipe(pin,sizeof pin);wipe(key,sizeof key);wipe(challenge,sizeof challenge);wipe(crypt,sizeof crypt);wipe(iv,sizeof iv);
 if(card){
  if(attempted){int reset=sc_reset(card,0);printf("RESET rv=%d\n",reset);if(reset<0)result=5;}
  if(locked){int unlock=sc_unlock(card);printf("UNLOCK rv=%d\n",unlock);if(unlock<0)result=6;}
  int disconnected=sc_disconnect_card(card);printf("DISCONNECT rv=%d\n",disconnected);if(disconnected<0)result=7;
 }
 printf("user_auth_attempts=%d; signatures=0\n",attempted);
 sc_release_context(ctx);return result;
}
