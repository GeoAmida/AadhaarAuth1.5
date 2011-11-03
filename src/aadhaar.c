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

#include "aadhaar.h"
#include "uid_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libxml/parser.h>

extern char * get_expiry_date(char *expiry);
extern unsigned char *uid_get_skey_data (unsigned char *key);
extern unsigned char *uid_get_aes_encrypted_data (unsigned char *in, int inlen, 
		 unsigned char *key);
extern int uid_encode_b64(unsigned char *in, int inlen, unsigned char *out, 
			int *outlen);
			
/**********************************
	Validate Aadhaar ID
**********************************/
int validate_uid( char *uId )
{
	int dMultTable[10][10] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}};
	int permTable[8][10] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8}};

	short int i=0, c=0;
	printf("validate_uid: %d:", c);
	for (i=0; i < 12; i++) {
		short int ni=0, newC=0;

		if (isdigit(uId[11-i]))
			ni = uId[11-i] - '0';
		else {
			printf("\n");
			return(-1);
		}
		newC = dMultTable[c][permTable[i%8][ni]];
		printf("%d:", newC);
		c = newC;
	}
	printf("\n");
	if (c == 0)
		return(0);
	return(-1);
}


char * parse_expiry_data(char *timestamp, char *expiry)
{
	
	char *strTimestamp=NULL;
	int n, k, mon, year, date;
	char m[][4] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

	strTimestamp = strtok(timestamp," ");
	if (strTimestamp != NULL) {
		int j;

		for (j=0; j < 12; j++) {
			if (strcmp(m[j],strTimestamp) == 0) {
				mon = j+1;
				break;
			}
		}
	}
	strTimestamp = strtok(NULL," ");
	if (strTimestamp != NULL)
		date = atoi(strTimestamp);
	strTimestamp = strtok(NULL," ");
	strTimestamp = strtok(NULL," ");
	if (strTimestamp != NULL)
		year = atoi(strTimestamp);
        sprintf(expiry, "%d%02d%02d", year, mon, date);
#ifdef DEBUG	
	printf("parse_expiry_data: value is :%s:\n", expiry);
#endif
	return expiry;
}

unsigned char* pidxml_demographic(char *pname)
{
	xmlNodePtr root, demo, bios, n;
	xmlDocPtr doc;
	xmlChar *xmlbuff;
	int buffersize;
	struct tm * curr_tm;
        time_t curr_time;
	char buff[50];

        curr_time = time(NULL);
        curr_tm = localtime(&curr_time);
        sprintf(buff, "%04d-%02d-%02dT%02d:%02d:%02d", curr_tm->tm_year+1900, 
		curr_tm->tm_mon+1, curr_tm->tm_mday, 
		curr_tm->tm_hour, curr_tm->tm_min, curr_tm->tm_sec);

	doc = xmlNewDoc(NULL);
	root = xmlNewNode(NULL, "Pid");
	xmlSetProp(root, "ts", buff);
	xmlSetProp(root, "ver", "1.0");
	xmlSetProp(root, "xmlns", "http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0");
	xmlDocSetRootElement(doc, root);

	demo = xmlNewNode(NULL, "Demo");
	n = xmlNewNode(NULL, "Pi");
	xmlSetProp(n, "ms", "E");
	xmlSetProp(n, "name", pname ? pname : "");
	xmlAddChild(demo, n);
	xmlAddChild(root, demo);

	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

	xmlFreeDoc(doc);
#if 1
	printf("\n############################################################\n%s\n", xmlbuff);
#endif
	return (unsigned char*)xmlbuff;
}

/***************************************************
	 Generate PID Xml - Biometric

	* tmplData - Encoded Biometric 
***************************************************/


unsigned char* pidxml_biometric(char *tmplData)
{
	xmlNodePtr root, demo, bios, n;
	xmlDocPtr doc;
	xmlChar *xmlbuff;
	int buffersize;
	struct tm * curr_tm;
        time_t curr_time;
	char buff[50];

        curr_time = time(NULL);
        curr_tm = localtime(&curr_time);
        sprintf(buff, "%04d-%02d-%02dT%02d:%02d:%02d", curr_tm->tm_year+1900, 
		curr_tm->tm_mon+1, curr_tm->tm_mday, 
		curr_tm->tm_hour, curr_tm->tm_min, curr_tm->tm_sec);

	doc = xmlNewDoc(NULL);
	root = xmlNewNode(NULL, "Pid");
	xmlSetProp(root, "ts", buff);
	xmlSetProp(root, "ver", "1.0");
	xmlSetProp(root, "xmlns", "http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0");
	xmlDocSetRootElement(doc, root);

	bios = xmlNewNode(NULL, "Bios");
	n = xmlNewNode(NULL, "Bio");
	xmlSetProp(n, "type", "FMR");
	xmlNodeSetContent(n, tmplData);
	xmlAddChild(bios, n);
	xmlAddChild(root, bios);

	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

	xmlFreeDoc(doc);
	printf("\n############################################################\n%s\n", xmlbuff);
	return (unsigned char*)xmlbuff;

}

/***************************************************
	 Generate Biometric  - Auth Xml
***************************************************/

unsigned char * authxml_biometric(char *puid, char *tmplData)	
{
	xmlNodePtr root, n;
	xmlDocPtr doc;
	xmlChar *preDigSignedXmlBuff, *digSignedXmlBuff;
	int buffersize;
	char *pidb, *encryptedSessKey=NULL, *pload, *hmac;
	unsigned char sessKey[32], shaHash[65];
	unsigned char txnId[32], devId[16];

	sprintf(txnId, "%d", rand());
	strcpy(duid, puid);
	printf("\n\nUid value is :%s\n",duid);

	doc = xmlNewDoc("1.0");
	root = xmlNewNode(NULL, "Auth");
	xmlSetProp(root, "xmlns", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0");
	xmlSetProp(root, "ver", "1.5");
	xmlSetProp(root, "tid", "public");
	xmlSetProp(root, "ac", "public");
	xmlSetProp(root, "sa", "public");
	xmlSetProp(root, "lk", LICENCE_KEY_ONE);
	xmlSetProp(root, "uid", puid ? puid : "");
	xmlSetProp(root, "txn", (const xmlChar *)txnId);
	xmlDocSetRootElement(doc, root);

	char bufExpiryStr[12];
	char *expiry=NULL;
	n = xmlNewNode(NULL, "Skey");
	xmlAddChild(root, n);
	{
		bzero(bufExpiryStr, 12);
		expiry = get_expiry_date(expiry);
		parse_expiry_data(expiry, bufExpiryStr);
		free(expiry);
		xmlSetProp(n, "ci", bufExpiryStr);
	}
	
	encryptedSessKey = uid_get_skey_data(sessKey);
	xmlNodeSetContent(n, encryptedSessKey);

	n = xmlNewNode(NULL, "Uses");
	xmlSetProp(n, "otp", "n"); //dpin as otp
	xmlSetProp(n, "pin", "n");
	xmlSetProp(n, "bio", "y");
	xmlSetProp(n, "pa", "n");
	xmlSetProp(n, "pfa", "n");
	xmlSetProp(n, "pi", "n");
	xmlSetProp(n, "bt", "FMR");
	xmlAddChild(root, n);

	pidb = pidxml_biometric(tmplData);
	n = xmlNewNode(NULL, "Data");
	xmlAddChild(root, n);
	pload = uid_get_aes_encrypted_data(pidb, strlen(pidb), sessKey);
	xmlNodeSetContent(n, pload);

	int res=hMacSha256(pidb, shaHash);

	hmac = uid_get_aes_encrypted_data(shaHash, SHA256_LENGTH, sessKey);
	n = xmlNewNode(NULL, "Hmac");
	xmlAddChild(root, n);
	xmlNodeSetContent(n, hmac);
	free(encryptedSessKey);
	free(hmac);

	xmlDocDumpFormatMemory(doc, &preDigSignedXmlBuff, &buffersize, 1);

	printf("\n\n AuthXML - 1:\n");
	printf("\n############################################################\n%s\n", preDigSignedXmlBuff);

#ifdef DEBUG	
	
	char str[7][256];

        sprintf(str[0], "echo size of base64 plain template buff is %d >> %s", strlen(tmplData), LOG_FILE);//Data in plain XML format
        system(str[0]);
        sprintf(str[1], "echo size of base64 template XML buff is %d >> %s", strlen(pidb), LOG_FILE);//Data in plain XML format
        system(str[1]);
        sprintf(str[2], "echo size of encrypted template buff is %d >> %s", strlen(pload), LOG_FILE);//Data in encrypted XML format
        system(str[2]);
        sprintf(str[3], "echo size of final encrypted xmlbuff is %d >> %s", strlen(preDigSignedXmlBuff), LOG_FILE); //final Data in Encrypted XML
        system(str[3]);
        sprintf(str[4], "echo -------------------------------------------------- >> %s", LOG_FILE);
        system(str[4]);
#endif	
	free(pidb);	
	free(pload);

#ifdef XML_SECURITY
	printf("\n############################################################\n");
	printf(" Digital Signature using XML Security\n\n");
	do_digital_signature(preDigSignedXmlBuff,&digSignedXmlBuff);
	if(preDigSignedXmlBuff)
		free(preDigSignedXmlBuff);
	xmlFreeDoc(doc);
	FILE *fp = fopen("/tmp/out.xml","w");
	fwrite(digSignedXmlBuff,1,strlen(digSignedXmlBuff),fp);
	fclose(fp);
	return ((unsigned char*)digSignedXmlBuff);
#else

	xmlFreeDoc(doc);
	return ((unsigned char*)preDigSignedXmlBuff);
#endif
}

/***************************************************
	 Generate Demographic  - Auth Xml
***************************************************/

unsigned char* authxml_demographic_details(char *puid, char *pname)	
{
	xmlNodePtr root, n;
	xmlDocPtr doc;
	xmlChar *preDigSignedXmlBuff, *digSignedXmlBuff;
	int buffersize;
	char *pidb, *encryptedSessKey=NULL, *pload, *hmac;
	unsigned char sessKey[32];
	unsigned char txnId[32], devId[16];
	unsigned char shaHash[64];	

	sprintf(txnId, "%d", rand());
	strcpy(duid, puid);

	doc = xmlNewDoc("1.0");
	root = xmlNewNode(NULL, "Auth");
	xmlSetProp(root, "xmlns", "http://www.uidai.gov.in/authentication/uid-auth-request/1.0");
	xmlSetProp(root, "ver", "1.5");
	xmlSetProp(root, "tid", "public");
	xmlSetProp(root, "ac", "public");
	xmlSetProp(root, "sa", "public");
	xmlSetProp(root, "lk", LICENCE_KEY_ONE);
	xmlSetProp(root, "uid", puid ? puid : "");
	xmlSetProp(root, "txn", (const xmlChar *)txnId);
	xmlDocSetRootElement(doc, root);

	char bufExpiryStr[12];
	char *expiry=NULL;
	n = xmlNewNode(NULL, "Skey");
	{
		bzero(bufExpiryStr, 12);
		expiry = get_expiry_date(expiry);
		parse_expiry_data(expiry, bufExpiryStr);
		free(expiry);
		xmlSetProp(n, "ci", bufExpiryStr);
	}
	xmlAddChild(root, n);
	
	encryptedSessKey = uid_get_skey_data(sessKey);
	xmlNodeSetContent(n, encryptedSessKey);

	n = xmlNewNode(NULL, "Uses");
	xmlSetProp(n, "otp", "n");
	xmlSetProp(n, "pin", "n");
	xmlSetProp(n, "bio", "n");
	xmlSetProp(n, "pa", "n");
	xmlSetProp(n, "pfa", "n");
	xmlSetProp(n, "pi", "y");
	xmlAddChild(root, n);

	pidb = pidxml_demographic(pname);
	n = xmlNewNode(NULL, "Data");
	xmlAddChild(root, n);
	pload =  uid_get_aes_encrypted_data(pidb, strlen(pidb), sessKey);
	xmlNodeSetContent(n, pload);

	int res=hMacSha256(pidb, shaHash);

	hmac = uid_get_aes_encrypted_data(shaHash, SHA256_LENGTH, sessKey);
	n = xmlNewNode(NULL, "Hmac");
	xmlAddChild(root, n);
	xmlNodeSetContent(n, hmac);
	free(encryptedSessKey);
	free(hmac);

	xmlDocDumpFormatMemory(doc, &preDigSignedXmlBuff, &buffersize, 1);
	free(pidb);
	free(pload);

#ifdef DEBUG
	printf("\n\n AuthXML - 1:\n");
	printf("\n############################################################\n%s\n", preDigSignedXmlBuff);
#endif

#ifdef XML_SECURITY
	printf("\nDigital Signature using XML Security\n\n");
	do_digital_signature(preDigSignedXmlBuff,&digSignedXmlBuff);
	free(preDigSignedXmlBuff);
	xmlFreeDoc(doc);
	return((unsigned char*)digSignedXmlBuff);
#endif	

	xmlFreeDoc(doc);
	return((unsigned char*)preDigSignedXmlBuff);
}


int uid_auth_demographic_details(char *puid, char *name)
{
	unsigned char *authb=NULL;
	int res;
	
	authb = authxml_demographic_details(puid, name);
	puts(authb);
	free(authb);
	
	return res;
}

int main()
{
	authxml_demographic_details("123456789012","Shiva");
	return 0;
}
