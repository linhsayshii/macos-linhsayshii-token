/* Compiles the vendored OASIS PKCS#11 headers so SwiftPM has a source to build.
 * No runtime code: the module is loaded via dlopen at runtime (see PKCS11.swift). */
#include "cpkcs11.h"
