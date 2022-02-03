Conscrypt - A Java Security Provider
========================================

Conscrypt is a Java Security Provider (JSP) that implements parts of the Java
Cryptography Extension (JCE) and Java Secure Socket Extension (JSSE).  It uses
BoringSSL to provide cryptographic primitives and Transport Layer Security (TLS)
for Java applications on Android and OpenJDK.  See [the capabilities
documentation](CAPABILITIES.md) for detailed information on what is provided.

The core SSL engine has borrowed liberally from the [Netty](http://netty.io/) project and their
work on [netty-tcnative](http://netty.io/wiki/forked-tomcat-native.html), giving `Conscrypt`
similar performance.

<table>
  <tr>
    <td><b>Homepage:</b></td>
    <td>
      <a href="https://conscrypt.org/">conscrypt.org</a>
    </td>
  </tr>
  <tr>
    <td><b>Mailing List:</b></td>
    <td>
      <a href="https://groups.google.com/forum/#!forum/conscrypt">conscrypt@googlegroups.com</a>
    </td>
  </tr>
</table>

Download
-------------
Conscrypt supports **Java 7** or later on OpenJDK and **Gingerbread (API Level
9)** or later on Android.  The build artifacts are available on Maven Central.

### Download JARs
You can download
[the JARs](http://search.maven.org/#search%7Cga%7C1%7Cg:%22org.conscrypt%22)
directly from the Maven repositories.

### OpenJDK (i.e. non-Android)

#### Native Classifiers

The OpenJDK artifacts are platform-dependent since each embeds a native library for a particular
platform. We publish artifacts to Maven Central for the following platforms:

Classifier | OS | Architecture
-----------| ------- | ---------------- |
linux-x86_64 | Linux | x86_64 (64-bit)
osx-x86_64 | Mac | x86_64 (64-bit)
windows-x86 | Windows | x86 (32-bit)
windows-x86_64 | Windows | x86_64 (64-bit)

#### Maven

Use the [os-maven-plugin](https://github.com/trustin/os-maven-plugin) to add the dependency:

```xml
<build>
  <extensions>
    <extension>
      <groupId>kr.motd.maven</groupId>
      <artifactId>os-maven-plugin</artifactId>
      <version>1.4.1.Final</version>
    </extension>
  </extensions>
</build>

<dependency>
  <groupId>org.conscrypt</groupId>
  <artifactId>conscrypt-openjdk</artifactId>
  <version>2.5.2</version>
  <classifier>${os.detected.classifier}</classifier>
</dependency>
```

#### Gradle
Use the [osdetector-gradle-plugin](https://github.com/google/osdetector-gradle-plugin)
(which is a wrapper around the os-maven-plugin) to add the dependency:

```gradle
buildscript {
  repositories {
    mavenCentral()
  }
  dependencies {
    classpath 'com.google.gradle:osdetector-gradle-plugin:1.4.0'
  }
}

// Use the osdetector-gradle-plugin
apply plugin: "com.google.osdetector"

dependencies {
  compile 'org.conscrypt:conscrypt-openjdk:2.5.2:' + osdetector.classifier
}
```

#### Uber JAR

For convenience, we also publish an Uber JAR to Maven Central that contains the shared
libraries for all of the published platforms. While the overall size of the JAR is
larger than depending on a platform-specific artifact, it greatly simplifies the task of
dependency management for most platforms.

To depend on the uber jar, simply use the `conscrypt-openjdk-uber` artifacts.

##### Maven
```xml
<dependency>
  <groupId>org.conscrypt</groupId>
  <artifactId>conscrypt-openjdk-uber</artifactId>
  <version>2.5.2</version>
</dependency>
```

##### Gradle
```gradle
dependencies {
  compile 'org.conscrypt:conscrypt-openjdk-uber:2.5.2'
}
```

### Android

The Android AAR file contains native libraries for x86, x86_64, armeabi-v7a, and
arm64-v8a.

#### Gradle

```gradle
dependencies {
  implementation 'org.conscrypt:conscrypt-android:2.5.2'
}
```


How to Build
------------

If you are making changes to Conscrypt, see the [building
instructions](BUILDING.md).


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
