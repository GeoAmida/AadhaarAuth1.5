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
*/

#include "uid_auth.h"

#ifdef XML_SECURITY
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#endif

unsigned char *uid_get_skey_data (unsigned char *key);
unsigned char *uid_get_aes_encrypted_data (unsigned char *in, int inlen, 
		 unsigned char *key);

/** 
 * sign_file:
 * @xmlInpData:		the XML data.
 *
 * Signs the @xml_file using private key from @key_file and dynamicaly
 * created enveloped signature template. The certificate from @cert_file
 * is placed in the <dsig:X509Data/> node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */

#ifdef XML_SECURITY
xmlChar * sign_file(char * xmlInpData)
{
	xmlChar *xmlBuff=NULL;
	xmlDocPtr doc=NULL;
	xmlNodePtr signNode=NULL, refNode=NULL, keyInfoNode=NULL;
	xmlSecDSigCtxPtr dsigCtx=NULL;
	int res=-1;
	X509 *x;
	EVP_PKEY *pkey;
	PKCS12 *p12;
	STACK_OF(X509) *ca=NULL;
	FILE *fp;

//	Storing Auth xml into Temp File so as to be read by xmlParseFile()
	fp = fopen(STORE_TEMP_AUTH_XML, "w");
	fwrite(xmlInpData, 1, strlen(xmlInpData), fp);
	fclose(fp);

	x = X509_new();

	fp = fopen(AUA_PRIVATE_CERTIFICATE, "rb");
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);

	if (!PKCS12_parse(p12, KEYPASS, &pkey, &x, &ca)) {
		printf(" Error while parsing\n");
	}
	PKCS12_free(p12);
	
// X509 Certificate
	fp = fopen(TEMP_STORE_CERTIFICATE,"w");
	PEM_write_X509(fp, x);
	fclose(fp);

// RSA Private Certificate
	fp = fopen(TEMP_STORE_KEY_CERTIFICATE,"w");
	PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(fp);

/* Load XML doc file */
	doc = xmlParseFile(STORE_TEMP_AUTH_XML);
	if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
		fprintf(stderr, "Error: unable to parse file \"%s\"\n",
			STORE_TEMP_AUTH_XML);
		if (doc != NULL)
			xmlFreeDoc(doc); 
		return(NULL);
	}
    
/* create signature template for RSA-SHA1 enveloped signature */
	signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformInclC14NId,
			xmlSecTransformRsaSha1Id, NULL);
	if (signNode == NULL) {
		fprintf(stderr, "Error: failed to create signature template\n");
		if (doc != NULL)
			xmlFreeDoc(doc); 
		return(NULL);
	}

/* add <dsig:Signature/> node to the doc */
	xmlAddChild(xmlDocGetRootElement(doc), signNode);
	refNode = xmlSecTmplSignatureAddReference(signNode,
			xmlSecTransformSha1Id, NULL, "", NULL);
	if (refNode == NULL) {
		fprintf(stderr, "Error: failed to add reference to signature template\n");
		if (doc != NULL)
			xmlFreeDoc(doc); 
		return(NULL);
	}

/* add enveloped transform */
	if (xmlSecTmplReferenceAddTransform(refNode,
		xmlSecTransformEnvelopedId) == NULL) {
		fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
		if (doc != NULL)
			xmlFreeDoc(doc); 
		return(NULL);
	}
    
/* add <dsig:KeyInfo/> and <dsig:X509Data/> */
	keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
	if (keyInfoNode == NULL) {
		fprintf(stderr, "Error: failed to add key info\n");
		if (doc != NULL)
			xmlFreeDoc(doc); 
		return(NULL);
	}
	xmlNodePtr x509Node=xmlSecTmplKeyInfoAddX509Data(keyInfoNode);

	xmlSecTmplX509DataAddSubjectName(x509Node);
	xmlSecTmplX509DataAddCertificate(x509Node);

/* create signature context, we don't need keys manager in this example */
	dsigCtx = xmlSecDSigCtxCreate(NULL);
	if (dsigCtx == NULL) {
		fprintf(stderr,"Error: failed to create signature context\n");
		if (doc != NULL)
			xmlFreeDoc(doc); 
		return(NULL);
	}
	
/* load private key, assuming that there is not password */
	dsigCtx->signKey = xmlSecCryptoAppKeyLoad(TEMP_STORE_KEY_CERTIFICATE,
		xmlSecKeyDataFormatPem, KEYPASS, NULL, NULL);
	if (dsigCtx->signKey == NULL) {
		fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", TEMP_STORE_KEY_CERTIFICATE);
		if (doc != NULL)
			xmlFreeDoc(doc); 
		if (dsigCtx != NULL)
			xmlSecDSigCtxDestroy(dsigCtx);
		return(NULL);
	}
    
/* load certificate and add to the key */
	if (xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, TEMP_STORE_CERTIFICATE,
		xmlSecKeyDataFormatPem) < 0) {
		fprintf(stderr,"Error: failed to load pem certificate \"%s\"\n", TEMP_STORE_CERTIFICATE);
		if (doc != NULL)
			xmlFreeDoc(doc); 
		if (dsigCtx != NULL)
			xmlSecDSigCtxDestroy(dsigCtx);
		return(NULL);
	}
/* sign the template */
	if (xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
		fprintf(stderr,"Error: signature failed\n");
		if (doc != NULL)
			xmlFreeDoc(doc); 
		if (dsigCtx != NULL)
			xmlSecDSigCtxDestroy(dsigCtx);
		return(NULL);
	}
	unlink(TEMP_STORE_KEY_CERTIFICATE);
	unlink(TEMP_STORE_CERTIFICATE);
	unlink(STORE_TEMP_AUTH_XML);
	{
		int bufferSize=0;

		xmlDocDumpFormatMemory(doc, &xmlBuff, &bufferSize, 1);
	}
#ifdef DEBUG
/* print signed document to stdout */
	xmlDocDump(stdout, doc);
#endif
	if (dsigCtx != NULL)
		xmlSecDSigCtxDestroy(dsigCtx);
	if (doc != NULL)
		xmlFreeDoc(doc); 
	return xmlBuff;
}
#endif

/*  Function: do_digital_signature 
	Parameters:
	1. Auth-Xml data
	2. Private Key File - PEM format
	3. Private Key password
	4. Certificate File - PEM format
*/
#ifdef XML_SECURITY
xmlChar * do_digital_signature(char *xmlInpData, xmlChar **out)
{
	xmlInitParser();
	LIBXML_TEST_VERSION
	xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
	xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
	xmlIndentTreeOutput = 1; 
#endif
        	
/* Init xmlsec library */
	if (xmlSecInit() < 0) {
		fprintf(stderr, "Error: xmlsec initialization failed.\n");
		return NULL;
	}

/* Check loaded library version */
	if (xmlSecCheckVersion() != 1) {
		fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
		return NULL;
	}

/* Load default crypto engine if we are supporting dynamic
 * loading for xmlsec-crypto libraries. Use the crypto library
 * name ("openssl", "nss", etc.) to load corresponding 
 * xmlsec-crypto library.
*/
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
	if (xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
		fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
		"that you have it installed and check shared libraries path\n"
		"(LD_LIBRARY_PATH) envornment variable.\n");
		return NULL;	
	}
#endif

/* Init crypto library */
	if (xmlSecCryptoAppInit(NULL) < 0) {
		fprintf(stderr, "Error: crypto initialization failed.\n");
		return NULL;
	}

/* Init xmlsec-crypto library */
	if (xmlSecCryptoInit() < 0) {
		fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
		return NULL;
	}
	*out = sign_file(xmlInpData);
   
#ifdef DEBUG
	printf("After Sign_file :%s\n\n",*out);
#endif	

	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();

#ifndef XMLSEC_NO_XSLT
	xsltCleanupGlobals();            
#endif
	xmlCleanupParser();
	return *out;
}
#endif

/*******************************************************
	 Retrieve Expiry Date from Certificate
*********************************************** *******/
char * get_expiry_date( char *expiryStr )
{
	X509 *x;
	unsigned char *not;
	int n=0;
	BIO *out;
	FILE *fp=fopen(UIDAI_PUBLIC_CERTIFICATE, "r");

	x = X509_new();
	x = PEM_read_X509(fp,NULL,NULL,NULL);
	fclose(fp);

	out = BIO_new(BIO_s_mem());
	ASN1_TIME_print(out, X509_get_notAfter(x));
	n = BIO_get_mem_data(out, &not);
	expiryStr = (char *) malloc (n+1);
	expiryStr[n] = '\0';
	memcpy(expiryStr, not, n);
	BIO_free(out);
	
	X509_free(x);
	return(expiryStr);
}

#ifdef DEBUG
int print_data(unsigned char *data, int datalen)
{
	int i;

	for (i=0; i < datalen; i++) {
		printf("%02x  ", data[i]);
		if ((i+1)%16 == 0)
			printf("\n");
	}
	printf("\n");
	return 0;
}
#endif

/*****************************************************
	Generates Sha256 hash
*****************************************************/

int hMacSha256(char *xml,unsigned char *outbuff)
{
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx,xml,strlen(xml));
	SHA256_Final(outbuff,&ctx);
	return 0;
}

/*****************************************************
	Assign RSA Key
*****************************************************/
int assign_key_rsa(RSA *rsa, unsigned char *key, int n_len, unsigned char *e_key, int e_len)
{
        rsa->n = BN_bin2bn(key, n_len, rsa->n);
        rsa->e = BN_bin2bn(e_key, e_len, rsa->e);
    	return 0;
}
/*****************************************************
	Generates Random Number
*****************************************************/

unsigned char * uid_random_bytes(unsigned char *rand, int len) 
{ 
	RAND_bytes(rand, len);
	return rand; 
}

/*****************************************************
	RSA Encryption
*****************************************************/

int uid_rsa_encrypt(unsigned char *in, int inlen, unsigned char *outbuf,
		int *outlen)
{
	unsigned char key[400]={0};
	unsigned char *pubKey;
	X509 *x;
	EVP_PKEY *epkey;
	int len, pubkey_len;
	FILE *fp; 
	ERR_load_crypto_strings();

	RSA *rsa = RSA_new();
	fp = fopen(UIDAI_PUBLIC_CERTIFICATE,"r");
	if(fp == NULL)
		printf(" NO UIDAI public Certificate found\n\n");
	x = PEM_read_X509(fp,NULL,0,NULL); // Read PEM Certificate from FILE
	fclose(fp);

	epkey = X509_get_pubkey(x);
	int bitSize = EVP_PKEY_size(epkey); // Bit Size
	BIGNUM *publickey = epkey->pkey.rsa->n; // modulus
	BIGNUM *exp = epkey->pkey.rsa->e; // exponential key
	pubKey = (unsigned char *)malloc(sizeof(unsigned char) * bitSize);
	unsigned char *eKey = (unsigned char *)malloc(sizeof(unsigned char)*100);
	
	int n_len = BN_bn2bin(publickey,pubKey); // convert it
	int e_len = BN_bn2bin(exp,eKey); // convert it

	memcpy(key,pubKey,n_len);
	assign_key_rsa(rsa, key,n_len,eKey,e_len);
	if (!EVP_PKEY_assign_RSA(epkey,rsa)) {
		printf("key assign error\n");
		return -1;
        }
	len = RSA_public_encrypt(inlen, in, outbuf, epkey->pkey.rsa,
			RSA_PKCS1_PADDING); //RSA_NO_PADDING
	*outlen = len;
	free(pubKey);
	EVP_PKEY_free(epkey);
	X509_free(x);
	return 0;
}
/*****************************************************
	AES Encryption
*****************************************************/

int uid_aes_encrypt(unsigned char *in, int inlen, unsigned char *out, 
		int *outlen, unsigned char *key, unsigned char *iv)
{
	int tmplen;
	// Straight encrypt

	EVP_CIPHER_CTX x;
	EVP_CIPHER_CTX_init(&x);
	
	EVP_CIPHER_CTX_set_padding(&x,1); // 1- padding, 0 - No Padding 

	if (!EVP_EncryptInit_ex(&x, EVP_aes_256_ecb(), NULL, key, iv)) {
		printf("\n ERROR!! \n");
		return -1;
	}
	if (!EVP_EncryptUpdate(&x, out, outlen,
			(const unsigned char*) in, inlen)) {
		printf("\n ERROR!! \n");
		return -2;
	}
	if (!EVP_EncryptFinal_ex(&x,out + *outlen,&tmplen)) {
		printf("\n ERROR!! \n");
		return -3;
	}
	*outlen += tmplen;
#ifdef DEBUG
	printf ("AES encrypted data %d len\n", *outlen);
	print_data (out, *outlen);
#endif
	EVP_CIPHER_CTX_cleanup(&x);
	return 0;
}
/*****************************************************
	Base64 Encoding
*****************************************************/

int uid_encode_b64(unsigned char *in, int inlen, unsigned char *out, 
			int *outlen)
{
	BIO *bmem=NULL, *b64=NULL;
	BUF_MEM *bptr=NULL;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, in, inlen);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	memcpy(out, bptr->data, bptr->length);
	out[bptr->length] = 0;
	*outlen = bptr->length;
	BIO_free_all(b64);
	return 0;
}
/*****************************************************
	Generates Session key
*****************************************************/
unsigned char *uid_get_skey_data(unsigned char *key)
{
	unsigned char OutRSA[512], *outData=NULL;
	int keyLen=0, OutRSALen=0, OutDataLen=0;

	memset(key, 0, 32);
	key = uid_random_bytes(key, RSA_KEY_LEN);
	keyLen = RSA_KEY_LEN;
	if (uid_rsa_encrypt(key, keyLen, OutRSA, &OutRSALen) != 0) {
		printf ("RSA encrypt failed\n");
		return NULL;
	}
	outData = (unsigned char *)malloc(sizeof(unsigned char)*512);

	uid_encode_b64(OutRSA, OutRSALen, outData, &OutDataLen);
	if (OutRSALen == 0) {
		printf ("uid_get_skey_data: base64 encode failed\n");
		return NULL;
	}
	outData[OutDataLen] = 0;
	return(outData);
}
/*****************************************************
	Aes Encryption with Base64
*****************************************************/

unsigned char *uid_get_aes_encrypted_data (unsigned char *in, int inlen, 
		 unsigned char *key)
{
	unsigned char iv[32]={0}, *temp, *out=NULL;
	int templen, outlen;
	
	temp = (char *)malloc(inlen+32);
	uid_aes_encrypt (in, inlen, temp, &templen, key, iv);		
	if (templen == 0){
		printf ("aes encrypt failed\n");	
		return NULL;
	}
	out = (char *)malloc(templen*4);
	uid_encode_b64(temp, templen, out, &outlen);
	if (outlen == 0){
		printf ("aes b64 encode failed\n");
		return NULL;
	}
	out[outlen] = 0;
	return out;
}
