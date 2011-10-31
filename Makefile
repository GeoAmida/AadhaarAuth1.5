#GCC compiler

CC=gcc
CFLAGS= -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XSLT=1 -DXMLSEC_NO_XKMS=1 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO=\"openssl\" -DUNIX_SOCKETS -DXML_SECURITY -DDEBUG
LDFLAGS= -lcrypto -I/usr/include/libxml2 -lxml2 -I/usr/local/include/xmlsec1 -lxmlsec1

$(CC) $(CFLAGS) $(LDFLAGS) src/aadhaar.c src/uid_auth.c -o AuthClient


#Geoamida Device - Cross Compile

CC = arm-xscale-linux-gnueabi-gcc
CFLAGS = -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_XSLT=1 -DXMLSEC_NO_XKMS=1 -I/opt/Olai/arm-xscale-linux-gnueabi/gcc-4.1.2-glibc-2.5-kernel-2.6.18/arm-xscale-linux-gnueabi/include/libxml2 -DXMLSEC_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO=\"openssl\" -DUNIX_SOCKETS -D XML_SECURITY

DFLAGS = -lwebcam -lbiometric -lautils -lpprinter -lxml2 -lcurl -lcrypto -lanet -I/opt/Olai/arm-xscale-linux-gnueabi/gcc-4.1.2-glibc-2.5-kernel-2.6.18/arm-xscale-linux-gnueabi/include/xmlsec1 -lxmlsec1 -g 

$(CC) $(CFLAGS) $(LDFLAGS) src/aadhaar.c src/uid_auth.c -o AuthClient


