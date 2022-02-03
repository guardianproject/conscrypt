#include <stdio.h>
#include <openssl/ssl.h>
//#include <Windows.h>
#include "server_Hello.h"

//#ifndef C_H
//#define C_H

/* This ifdef allows the header to be used from both C and C++ 
 * because C does not know what this extern "C" thing is. */
/*#ifdef __cplusplus
#include <openssl/ssl.h>
int SSL_export_keying_material(SSL *, uint8_t *, size_t ,const char *, size_t ,const uint8_t *, size_t ,int);
extern "C" {
#endif
//bool SSL_export_keying_material(ssl, buf_out,olen, buf_label,len_label,0 ,0, 0);
#include <openssl/ssl.h>
int SSL_export_keying_material(SSL *, uint8_t *, size_t ,const char *, size_t ,const uint8_t *, size_t,int );
#ifdef __cplusplus
}
#endif

#endif*/
extern "C" int SSL_export_keying_material(SSL *, uint8_t *, size_t ,const char *, size_t ,const uint8_t *, size_t,int );
//#include <nativehelper/scoped_primitive_array.h>
//#include <nativehelper/scoped_utf_chars.h>
/*
#include "conscrypt/NetFd.h"
#include "conscrypt/app_data.h"
#include "conscrypt/bio_input_stream.h"
#include "conscrypt/bio_output_stream.h"
#include "conscrypt/bio_stream.h"
#include "conscrypt/compat.h"
#include "conscrypt/compatibility_close_monitor.h"
#include "conscrypt/jniutil.h"
#include "conscrypt/logging.h"
#include "conscrypt/macros.h"
#include "conscrypt/native_crypto.h"
#include "conscrypt/netutil.h"
#include "conscrypt/scoped_ssl_bio.h"
#include "conscrypt/ssl_error.h"

#include "nativehelper/scoped_primitive_array.h"
#include "nativehelper/scoped_utf_chars.h"

#include <limits.h>

#include <openssl/aead.h>
#include <openssl/asn1.h>
#include <openssl/chacha.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs8.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>*/
//typedef int (*TestExportKeyingMFunc)(SSL, unsigned char *,size_t,const char *,size_t, const unsigned char *, size_t,int); 
//typedef int (__cdecl *MYPROC)(SSL*, unsigned char *,size_t,const char *,size_t, const unsigned char *, size_t,int);
JNIEXPORT void JNICALL Java_server_Hello_sayHi(JNIEnv *env, jobject obj, jstring who, jint times) {
  jint i;
  jboolean iscopy;
  const char *name;
  //name = (*env)->GetStringUTFChars(env, who, &iscopy);
  name = env->GetStringUTFChars( who, &iscopy);
  for (i = 0; i < times; i++) {
    printf("Hello %s\n", name);
  }
}
/*static SSL* to_SSL(JNIEnv* env, jlong ssl_address, bool throwIfNull) {
    SSL* ssl = reinterpret_cast<SSL*>(static_cast<uintptr_t>(ssl_address));
    if ((ssl == nullptr) && throwIfNull) {
        JNI_TRACE("ssl == null");
        conscrypt::jniutil::throwNullPointerException(env, "ssl == null");
    }
    return ssl;
}*/
JNIEXPORT void JNICALL Java_server_Hello_exportKeyingMaterian(JNIEnv * env, jobject object, 
	jobject ssl_address, jbyteArray out, jlong olen, jcharArray label, jlong llen, jcharArray context, jlong contextlen, jint use_context){

	// Function start with getting the address of SSLSoket object poiter and pass as first parameter
	printf("Hello %s\n", "started Java_server_Hello_exportKeyingMaterian");
	void * dfuffadd=env->GetDirectBufferAddress(ssl_address);
	printf("%s %ld", "GetDirectBufferAddress ssl_address=", dfuffadd);
    jlong dfuffCapadd=env->GetDirectBufferCapacity(ssl_address);
    printf("%s %ld", "etDirectBufferCapacity ssl_address=", dfuffCapadd);
    jobject add=env->NewGlobalRef( ssl_address);
    printf("%s %ld", "NewGlobalRef ssl_address=", add);
	printf("Hello %s%x\n", "address of ssl using NewGlobalRef =",add);
    jobject ssljobject = env->NewGlobalRef(ssl_address);
    printf("ssljobject = %x\n", ssljobject);
	


	SSL* ssl = reinterpret_cast<SSL*>(add);
	printf("ssl = %x\n", ssl);
	if (ssl == NULL) {
		printf("Hello %s\n", "ssl is null returning");
        return ;
    }
	printf("Hello %s\n", "ssl is Non-null returning lets check out");
	printf("  olen= %d\n", olen);
	int len_out = env->GetArrayLength (out);
    uint8_t* buf_out = new uint8_t[olen];
    //env->GetCharArrayRegion (out, 0, len_out, reinterpret_cast<jchar*>(buf_out));
    printf("buf_out= %x\n", buf_out);

    jlong len_label = llen; // line of pseudo code
	printf("  len_label= %d\n", len_label);
	printf("  label= %x\n", label);
	jsize label_size = env->GetArrayLength( label);
	printf("  label_size= %d\n", label_size);
	jchar *body = env->GetCharArrayElements( label, 0);
	printf("  body= %s\n", body);
	for(int i=0; i < label_size; i++) {
	  printf("Char value: %c\n", body[i]);
	}
	len_label =label_size;
	const char* buf_label = reinterpret_cast<char*>(body);
	printf("  buf_label= %x\n", buf_label);
	 printf("Hello %s\n", "after sslclass Java_packagejni_Hello_exportKeyingMaterian called");
	//const char * sslver_ret=SSL_get_version(ssl);
	//printf("sslver_ret full string= : %s\n", sslver_ret);
	//while(*sslver_ret!='\0') printf("%c",*sslver_ret++);

    //unsigned char *out=calloc(sizeof(char), olen);
	//pass anew temp cha * of array equeal in size of llen and pass to EportFunt()
	// After you receive the result then use SetCharArrayRegion to update jcharArray with new value
	 int status=0;
    status = SSL_export_keying_material(ssl, buf_out,olen, buf_label,len_label,0 ,0, 0);
		        if(status){
		        	printf("%s\n","Cal to SSL_export_keying_material API is successful" );
		        	printf("%s\n","Coppying data to out array" );
			    	for(int i=0; i < olen; i++) {
						  printf("output buf_out: %c\n", buf_out[i]);
						}
			    	printf("%s\n","Finished Coppying data to out array" );

			    	jbyteArray result = env->NewByteArray(static_cast<jsize>(olen));
				    if (result) {
				    	printf("%s\n","starting SetByteArrayRegion Coppying" );
				        const jbyte* src = reinterpret_cast<jbyte*>(buf_out);
				        env->SetByteArrayRegion(result, 0, static_cast<jsize>(olen), src);
				        printf("ssl=%p NativeCrypto_SSL_export_keying_material => success", ssl);

				    }
				    
			    	return; 

			    }
			    else{
			    	printf("%s\n","Cal to SSL_export_keying_material API is unsuccessful return false" );

			    }
    const unsigned char *context1={};
    /*int status = 0;
    //TestExportKeyingMFunc _TestFunc;
    MYPROC ProcAdd; 
    HINSTANCE testLibrary = LoadLibrary(TEXT("D:\\SSL-Client-Server\\src\\main\\java\\ssl.dll"));
    //HINSTANCE testLibrary = LoadLibrary(TEXT("D:\\tmp\\libssl-1_1-x64.dll"));
    if (testLibrary)
    {
    	printf("Hello %s\n", "after testLibrary Java_packagejni_Hello_exportKeyingMaterian called");
    	//Java_server_Hello_exportKeyingMaterian
    	//SSL_export_keying_material
        ProcAdd = (MYPROC) GetProcAddress(testLibrary, "SSL_export_keying_material");

        if (ProcAdd)
        {
           //status = _TestFunc();
        	printf("Hello %s\n", "after ProcAdd Java_packagejni_Hello_exportKeyingMaterian called");
        	if (ssl) {
        		//char * c=(char *)context;
        		
		        printf("%s\n","ssl is not null calling SSL_export_keying_material API" );
			    void * n=NULL;
		        status = ProcAdd(ssl, buf_out,olen, buf_label,len_label,0 ,0, 0);
		        if(status){
		        	printf("%s\n","Cal to SSL_export_keying_material API is successful" );
		        	printf("%s\n","Coppying data to out array" );
		        	//char* tmpbuff = reinterpret_cast<char*>(buf_out);
			    	for(int i=0; i < olen; i++) {
						  printf("output buf_out: %x\n", buf_out[i]);
						}
			    	printf("%s\n","Finished Coppying data to out array" );
			    	env->SetByteArrayRegion (out, 0, len_out, reinterpret_cast<jbyte*>(buf_out));
			    	jbyteArray result = env->NewByteArray(static_cast<jsize>(olen));
				    if (out) {
				    	printf("%s\n","starting SetByteArrayRegion Coppying" );
				        for(int i=0; i < olen; i++) {
						  printf("output out: %x\n", out[i]);
						}
				        printf("ssl=%p NativeCrypto_SSL_export_keying_material => success", ssl);
				    }
			    	return; 
			    }
			    else{
			    	printf("%s\n","Cal to SSL_export_keying_material API is unsuccessful return false" );

			    }

		    }
		    else{
		    	printf("%s\n","ss is null" );
		    	//status = ProcAdd(ssl, buf_out, buf_label, NULL,0,NULL ,0, 1);
		        return; 
		    }
		    
		    //env->SetCharArrayRegion(out, 0, sizeof(version_len), j_version);
           
        }else{
        printf("Hello %s\n", "ProcAdd is null");        	
        }
        
        FreeLibrary(testLibrary);

    }
    else{
        printf("Hello %s\n", "testLibrary is null");        	
    }*/
    


	//convert jcharArray context to chat [] and pass it to funtion if its not null as well as contextlen
	

	//convert use_context to int and pass on to funtion

	
    //int ret = SSL_export_keying_material(ssl, buffer, 20, "",0,context1 ,0, 1);
    /*

    jchar* j_version = (jchar*)calloc(sizeof(jchar), sizeof(buffer));
	for(int i=0; i <= sizeof(buffer); i++){
	    j_version[i] =  (jchar) buffer[i];
	}*/

    /*if(ret){
    	//env->SetCharArrayRegion(out, 0, sizeof(version_len), j_version);

    }
    else{

    }*/

    
}
