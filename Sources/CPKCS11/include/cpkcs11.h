#ifndef CPKCS11_SHIM_H
#define CPKCS11_SHIM_H

/* The OASIS PKCS#11 headers require these platform macros before inclusion.
 * UNIX definitions per the header's own guidance. */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/* The published OASIS v3.0 pkcs11t.h has an erratum: CK_HKDF_PARAMS references
 * CK_BOOL and CK_HANDLE, which the header never typedefs. Supply them here
 * (matching CK_BBOOL / CK_OBJECT_HANDLE) so the vendored file compiles unedited. */
typedef unsigned char     CK_BOOL;
typedef unsigned long int CK_HANDLE;

#include "pkcs11.h"

#endif
