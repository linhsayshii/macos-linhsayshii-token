// EFY-CA metadata/certificate probe. No C_Login, C_Sign or mutating PKCS#11 calls.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
#include "cpkcs11.h"
static void sha(const unsigned char *p,size_t n,char out[65]) {
 unsigned char h[32]; CC_SHA256(p,(CC_LONG)n,h);for(int i=0;i<32;i++)sprintf(out+i*2,"%02x",h[i]);out[64]=0;
}
static unsigned char *attr(CK_FUNCTION_LIST_PTR f,CK_SESSION_HANDLE s,CK_OBJECT_HANDLE o,CK_ATTRIBUTE_TYPE t,CK_ULONG *n) {
 CK_ATTRIBUTE a={t,NULL,0};CK_RV r=f->C_GetAttributeValue(s,o,&a,1);
 if(r || a.ulValueLen==CK_UNAVAILABLE_INFORMATION || a.ulValueLen>1048576)return NULL;
 unsigned char *p=malloc(a.ulValueLen+1);if(!p)return NULL;a.pValue=p;r=f->C_GetAttributeValue(s,o,&a,1);
 if(r){free(p);return NULL;}*n=a.ulValueLen;return p;
}
int main(int argc,char **argv) {
 if(argc!=3)return 2;setvbuf(stdout,NULL,_IONBF,0);
 void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h){fprintf(stderr,"dlopen=%s\n",dlerror());return 3;}
 CK_C_GetFunctionList get=(CK_C_GetFunctionList)dlsym(h,"C_GetFunctionList");if(!get)return 4;
 CK_FUNCTION_LIST_PTR f=NULL;CK_RV r=get(&f);printf("C_GetFunctionList=0x%lx\n",r);if(r||!f)return 5;
 r=f->C_Initialize(NULL);printf("C_Initialize=0x%lx\n",r);if(r)return 6;
 CK_INFO info={0};r=f->C_GetInfo(&info);printf("C_GetInfo=0x%lx; Cryptoki=%u.%u; manufacturer=%.32s; library=%u.%u\n",r,info.cryptokiVersion.major,info.cryptokiVersion.minor,info.manufacturerID,info.libraryVersion.major,info.libraryVersion.minor);
 for(int present=0;present<2;present++) {
  CK_ULONG n=0;r=f->C_GetSlotList(present,NULL,&n);printf("Slots.present=%d; rv=0x%lx; count=%lu\n",present,r,n);if(r||n>64||!n)continue;
  CK_SLOT_ID slots[64];r=f->C_GetSlotList(present,slots,&n);if(r||n>64)continue;
  for(CK_ULONG i=0;i<n;i++) {
   CK_SLOT_INFO si={0};r=f->C_GetSlotInfo(slots[i],&si);printf("Slot=%lu; rv=0x%lx; description=%.64s\n",slots[i],r,si.slotDescription);if(!present){CK_TOKEN_INFO pre={0};CK_RV pr=f->C_GetTokenInfo(slots[i],&pre);printf("Token.preflight.slot=%lu; rv=0x%lx\n",slots[i],pr);continue;}
   CK_TOKEN_INFO ti={0};r=f->C_GetTokenInfo(slots[i],&ti);printf("Token.slot=%lu; rv=0x%lx; manufacturer=%.32s; model=%.16s; flags=0x%lx\n",slots[i],r,ti.manufacturerID,ti.model,ti.flags);if(r)continue;
   CK_ULONG count=0;r=f->C_GetMechanismList(slots[i],NULL,&count);printf("Mechanisms.rv=0x%lx; count=%lu\n",r,count);
   if(!r&&count<=256){CK_MECHANISM_TYPE ms[256];r=f->C_GetMechanismList(slots[i],ms,&count);if(!r&&count<=256)for(CK_ULONG j=0;j<count;j++){CK_MECHANISM_INFO mi={0};r=f->C_GetMechanismInfo(slots[i],ms[j],&mi);printf("Mechanism=0x%lx; rv=0x%lx; min=%lu; max=%lu; flags=0x%lx\n",ms[j],r,mi.ulMinKeySize,mi.ulMaxKeySize,mi.flags);}}
   CK_SESSION_HANDLE s=0;r=f->C_OpenSession(slots[i],CKF_SERIAL_SESSION,NULL,NULL,&s);printf("C_OpenSession.RO=0x%lx\n",r);if(r)continue;
   CK_OBJECT_CLASS cls=CKO_CERTIFICATE;CK_ATTRIBUTE a={CKA_CLASS,&cls,sizeof(cls)};r=f->C_FindObjectsInit(s,&a,1);printf("FindCertificates.init=0x%lx\n",r);
   if(!r){for(int j=0;j<32;j++){CK_OBJECT_HANDLE o=0;CK_ULONG found=0;r=f->C_FindObjects(s,&o,1,&found);if(r||!found)break;CK_ULONG len=0;unsigned char *der=attr(f,s,o,CKA_VALUE,&len);if(der){char hash[65],name[1024];sha(der,len,hash);snprintf(name,sizeof(name),"%s/slot%lu-cert%d.der",argv[2],slots[i],j);FILE *fp=fopen(name,"wb");if(fp){fwrite(der,1,len,fp);fclose(fp);chmod(name,0600);}printf("Certificate.slot=%lu; index=%d; DERbytes=%lu; SHA256=%s\n",slots[i],j,len,hash);free(der);}CK_ULONG il=0;unsigned char *id=attr(f,s,o,CKA_ID,&il);if(id){char hs[65];sha(id,il,hs);printf("Certificate.CKA_ID.bytes=%lu; SHA256=%s\n",il,hs);free(id);}}printf("FindCertificates.final=0x%lx\n",f->C_FindObjectsFinal(s));}
   printf("C_CloseSession=0x%lx\n",f->C_CloseSession(s));
  }
 }
 printf("C_Finalize=0x%lx\n",f->C_Finalize(NULL));dlclose(h);return 0;
}
