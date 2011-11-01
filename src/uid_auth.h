/*
    Copyright (C) 2011 Geodesic Limited, Mumbai, India

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
    INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE X CONSORTIUM BE LIABLE
    FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
    OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

	Except as contained in this notice, the name of the Geodesic Limited shall not be used
	in advertising or otherwise to promote the sale, use or other dealings in this Software
	without prior written authorization from the Geodesic Limited.

*/



#ifndef __UID_AUTH__
#define __UID_AUTH__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/pkcs12.h>

#ifdef SERVER_PRODUCTION
#define UIDAI_PUBLIC_CERTIFICATE "/tmp/alive_auth/uid_prod.cer"
#define AUA_PRIVATE_CERTIFICATE "/tmp/public.p12"
#else
#define UIDAI_PUBLIC_CERTIFICATE "/tmp/uidai_auth_stage.cer"
#define AUA_PRIVATE_CERTIFICATE "/tmp/public.p12"
#endif

#define MAX_PUBKEY_SIZE   256
#define RSA_KEY_OFFSET    27
#define AES_KEY_LEN       32  // Changed according to spec 1.5 rev 1
#define RSA_KEY_LEN       32  // Changed according to spec 1.5 rev 1

#define STORE_TEMP_AUTH_XML "auth-xml.xml"
#define TEMP_STORE_CERTIFICATE "/tmp/cer" // Data of X509 Certicate Tag
#define TEMP_STORE_KEY_CERTIFICATE "/tmp/pri" // Private Key PEM File

#define KEYPASS "public"

/*unsigned char *uid_get_skey_data (unsigned char *key);
unsigned char *uid_get_aes_encrypted_data (unsigned char *in, int inlen, 
		 unsigned char *key);*/
#endif
