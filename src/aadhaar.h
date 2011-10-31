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

#ifdef __cplusplus
}
#endif

#endif
