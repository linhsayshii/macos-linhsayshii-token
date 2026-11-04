#include "cpkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Deliberately no login, sign, write, format, or PIN entry path.
static void fixed(const char *name, const CK_UTF8CHAR *p, size_t n) {
    while (n && (p[n-1] == ' ' || p[n-1] == 0)) n--;
    printf("%s=%.*s\n", name, (int)n, p);
}
int main(int argc, char **argv) {
    setbuf(stdout, NULL); alarm(25);
    if (argc < 2 || argc > 3) return 2;
    #if defined(__arm64__)
    const char *arch="arm64";
#else
    const char *arch="x86_64";
#endif
    printf("probe_arch=%s pointer=%zu CK_ULONG=%zu module=%s\n",arch,sizeof(void*),sizeof(CK_ULONG),argv[1]);
    void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if (!h) {printf("dlopen_error=%s\n",dlerror());return 3;}
    CK_C_GetFunctionList get=(CK_C_GetFunctionList)dlsym(h,"C_GetFunctionList");
    if (!get) return 4;
    CK_FUNCTION_LIST_PTR f=NULL;CK_RV rv=get(&f);printf("C_GetFunctionList=0x%lx\n",rv);if(rv||!f)return 5;
    printf("cryptoki=%u.%u\n",f->version.major,f->version.minor);
    rv=f->C_Initialize(NULL);printf("C_Initialize=0x%lx\n",rv);if(rv && rv!=CKR_CRYPTOKI_ALREADY_INITIALIZED)return 6;
    CK_INFO info={0};rv=f->C_GetInfo(&info);printf("C_GetInfo=0x%lx\n",rv);
    if(!rv){fixed("manufacturer",info.manufacturerID,32);fixed("description",info.libraryDescription,32);}
    if (argc == 3) {
        char *criteria=dlsym(h,"g_p11_device_criteria");
        if(!criteria || strlen(argv[2])>=256)return 7;
        // Exported 256-byte data global; avoid buggy vendor M_SetEnumString (strncpy 1024).
        strcpy(criteria,argv[2]);
        CK_RV (*setDeviceEnum)(char*,char*)=dlsym(h,"MKF_SetEnumDeviceString");
        if(setDeviceEnum)printf("MKF_SetEnumDeviceString=0x%lx\n",setDeviceEnum(criteria,NULL));
        printf("local_criteria=%s\n",criteria);
    }
    if (getenv("ONECA_USB_DIAG")) {
    void *usbctx=NULL;void **devs=NULL;
    int (*usbinit)(void**)=dlsym(h,"libusb_init");
    ssize_t (*usblist)(void*,void***)=dlsym(h,"libusb_get_device_list");
    int (*usbdesc)(void*,void*)=dlsym(h,"libusb_get_device_descriptor");
    void (*usbfree)(void**,int)=dlsym(h,"libusb_free_device_list");
    void (*usbexit)(void*)=dlsym(h,"libusb_exit");
    int ur=usbinit(&usbctx);printf("libusb_init=%d\n",ur);
    if(!ur){ssize_t nn=usblist(usbctx,&devs);printf("libusb_get_device_list=%zd\n",nn);
        for(ssize_t q=0;q<nn && q<64;q++){unsigned char ds[18]={0};ur=usbdesc(devs[q],ds);if(!ur)printf("usb_device=%04x:%04x\n",ds[8]|(ds[9]<<8),ds[10]|(ds[11]<<8));}
        // Exit the isolated diagnostic process; do not share libusb teardown with Cryptoki.
        if(nn>=0)usbfree(devs,1);return 0;
    }
    }
    printf("before_slots f=%p slotlist=%p getinfo=%p\n",f,f->C_GetSlotList,f->C_GetInfo);
    for(int present=0;present<=1;present++) {
        CK_ULONG n=0;rv=f->C_GetSlotList(present,NULL,&n);printf("C_GetSlotList present=%d rv=0x%lx count=%lu\n",present,rv,n);
        if(rv||!n||n>64)continue;CK_SLOT_ID slots[64]={0};rv=f->C_GetSlotList(present,slots,&n);if(rv)continue;
        for(CK_ULONG i=0;i<n;i++) {
            CK_SLOT_INFO si={0};rv=f->C_GetSlotInfo(slots[i],&si);printf("slot=%lu info_rv=0x%lx flags=0x%lx\n",slots[i],rv,si.flags);fixed("reader",si.slotDescription,64);
            CK_TOKEN_INFO ti={0};rv=f->C_GetTokenInfo(slots[i],&ti);printf("token_rv=0x%lx flags=0x%lx\n",rv,ti.flags);if(rv)continue;
            fixed("label",ti.label,32);fixed("model",ti.model,16);fixed("serial",ti.serialNumber,16);
            if(!present)continue;
            CK_ULONG nm=0;rv=f->C_GetMechanismList(slots[i],NULL,&nm);printf("mechanisms_rv=0x%lx count=%lu\n",rv,nm);
            if(!rv && nm<=128){CK_MECHANISM_TYPE ms[128];rv=f->C_GetMechanismList(slots[i],ms,&nm);for(CK_ULONG m=0;!rv&&m<nm;m++)printf("mechanism=0x%lx\n",ms[m]);}
            CK_SESSION_HANDLE session;rv=f->C_OpenSession(slots[i],CKF_SERIAL_SESSION,NULL,NULL,&session);printf("open_readonly_rv=0x%lx\n",rv);if(rv)continue;
            CK_OBJECT_CLASS cl=CKO_CERTIFICATE;CK_ATTRIBUTE attr={CKA_CLASS,&cl,sizeof(cl)};
            rv=f->C_FindObjectsInit(session,&attr,1);printf("find_init_rv=0x%lx\n",rv);
            if(!rv){for(unsigned k=0;k<32;k++){CK_OBJECT_HANDLE obj;CK_ULONG count=0;rv=f->C_FindObjects(session,&obj,1,&count);if(rv||!count)break;
                CK_ATTRIBUTE a[2]={{CKA_ID,NULL,0},{CKA_VALUE,NULL,0}};rv=f->C_GetAttributeValue(session,obj,a,2);printf("certificate=%u attr_rv=0x%lx id_len=%lu der_len=%lu\n",k,rv,a[0].ulValueLen,a[1].ulValueLen);
                // Metadata only: keep personal certificate contents out of this log.
            }f->C_FindObjectsFinal(session);}f->C_CloseSession(session);
        }
    }
    rv=f->C_Finalize(NULL);printf("C_Finalize=0x%lx\n",rv);return 0;
}
