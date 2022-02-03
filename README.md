HTTP Transport Authentication
========================================
IETF draft (draft-schinazi-httpbis-transport-auth-00)
defines a mechanism to autbenticate the transport layer protocols in user level (HTTP layers). This code implened the draft by extending the  Conscrypt which is Java Security Provider (JSP) that implements parts of the Java
Cryptography Extension (JCE) and Java Secure Socket Extension (JSSE).  It uses
BoringSSL to provide cryptographic primitives and Transport Layer Security (TLS) for Java.

The conscrypt is build using gradle and depends on boringssl. You first need to build the boringssl as mentioned in BUILD.md and set relevant environment variable for conscrypt. Upon buolding the conscrypt it use the static libraries of boringssl (ssl, crypto etc) and write a Jana native Interface(JNI) wrapper for it. The resultant classes can call the booringssl c++ function/api from Java/android code. The conscrupt gradle projects once build it link the booringssl and JNI wrapper into a shared library (on linux .so) for c++ native functions as well as jars for other pure java code of conscrypt.

We have added two java new modules into conscrypt android studio project. Conscrypt-transportauthclient is the implementation of transport authentication client which uses TLS1.2 socket (conscrypt with boringssl) to generate transport authentication header and send requests to server.
Conscrypt-transportauth module contains a java server using conscrypt as default security provider. Once a client connects to the server after  handshake the keying materials are exported out of session using JNI wrapper.

After transport header fields verification, and which also involves cryptography algorithm specified by client. Both symmetric and asymmetric are supported. HMAC is used for symmetric and Signature keyword is used to define the asymmetric transport parameters. Value of 'a' describes the algorithm 'u' base64 encoded username and 'p' proof of authentication. As per draft we use two different keying material exported label each for symmetric and asymmetric algorithms. The implementation uses  is the SHA256withRSA as Signature and HMAC256 as HMAC algorithm. After the users TLS all parameters including proof is authenticated the username and public key is stored as key value pair and used and HTTP OK response is sent back to the client.


How to Build and Run
-----------------------------

If you are making changes to Transport Authentication, 
 see the [building
instructions](BUILD.md).
