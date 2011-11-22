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

/*! 	\file aadhaar.h
*/

/*! \mainpage Aaddhaar Auth XML Generation API - Version 1.5
 *
 * \section intro_sec Introduction
 *
 * This documentation contains the details about how to use the Aadhaar API's to generate Auth XML version 1.5 in your Application.
 *
 *
 *
 * Dependencies:
 *
 *	The following libraries are required.
 *
 *	* Openssl 0.9.8 or above 
 *
 *	* LibXml 2.7.6 or above 
 *
 *
 * Additional Dependencies for Digital Signature Generation:
 * 
 * 	* libXslt
 *
 *  * libXmlSec1
 *
 * Note:
 *  
 *	You have to include the header file aadhaar.h in your application to use API's.
 *   
 *	While compiling your application you have to link the library -lcrypto -lxml2.
 *
 *  If Digital Signature used, then -lxslt -lxmlsec1 should be linked.
 *
 * 	example: gcc filename.c <linking_libraries>
 *
 * *
 */
#ifndef __AADHAAR_H__
#define __AADHAAR_H__

#ifdef __cplusplus
extern "C" {
#endif

/*! \def SHA256_LENGTH
 * \brief Sha 256 Length, used by Hmac function to generate Hash value.
 */
#define SHA256_LENGTH 32

/*! \def LOG_FILE
 * \brief log file location to store logs for debugging purpose.
 */
#define LOG_FILE "/tmp/log.txt"
/*! \def LICENCE_KEY_ONE
 * \brief Licence Key, Used by AuthXml lk attribute.
 */
#define LICENCE_KEY_ONE "MKg8njN6O+QRUmYF+TrbBUCqlrCnbN/Ns6hYbnnaOk99e5UGNhhE/xQ="

char duid[16];
char fdc[11]; // fdc attribute

/*!\fn unsigned char * pidxml_demographic(char *pname)
 * \brief This function is used to generate demographic PID XML data by sending Name as parameter. Returns XML data
 *
 * \param pname.
 *
 * \return xmldata.
 */
unsigned char * pidxml_demographic(char *pname);
/*!\fn unsigned char * pidxml_biometric(char *tmpldata)
 * \brief This function is used to generate biometric PID XML data by sending encoded fingerprint template as parameter. Returns XML data
 *
 * \param tmpldata.
 *
 * \return xmldata.
 */
unsigned char * pidxml_biometric(char *tmplData);
/*!\fn unsigned char * authxml_demographic_details(char *puid, char *pname)
 * \brief This function is used to generate Demographic Auth XML by sending parameter values of Aadhaar id and Name. Returns XML data
 *
 * \param puid
 * \param pname.
 *
 * \return xmldata.
 */
unsigned char * authxml_demographic_details(char *puid, char *pname);
/*!\fn unsigned char * authxml_biometric(char *puid, char *tmplData)
 * \brief This function is used to generate Biometric Auth XML by sending parameter values of Aadhaar id and Encoded fingerprint template data. Returns XML data
 *
 * \param puid
 * \param tmplData.
 *
 * \return xmldata.
 */
unsigned char * authxml_biometric(char *puid, char *tmplData);	
/*!\fn unsigned char * authxml_biometric_with_fdc(char *puid, char *pfdc, char *tmplData)
 * \brief This function is used to generate Biometric Auth XML by sending parameter values of Aadhaar id, fdc value and Encoded fingerprint template data. Returns XML data
 *
 * \param puid
 * \param pfdc
 * \param tmplData
 *
 * \return xmldata.
 */
unsigned char * authxml_biometric_with_fdc(char *puid, char *pfdc, char *tmplData);


/*!\fn int validate_uid(char *uId)
 * \brief This function is used to validate Aadhaar ID by sending parameter value of Aadhaar id. Return value 0 or -1.
 *
 * \param uId
 *
 * \return value. 0 for Success, -1 for failure.
 */
int validate_uid( char *uId );

#ifdef __cplusplus
}
#endif

#endif
