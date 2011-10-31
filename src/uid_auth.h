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
