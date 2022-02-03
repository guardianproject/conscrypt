Building Transport Authentication leveraging Conscrypt
==================


Instruction for using prebuild dependencies on Linux x64:
--------------------------------------------------------
1. conscrypt-transportauth module is java module with gradle as build tool. The class HTTPSServer run the Transprt Authentication server. This class has two dependencies 
i) Two jar files ( conscrypt-openjdk-2.5.0-SNAPSHOT-linux-x86_64.jar and conscrypt-openjdk-2.5.0-SNAPSHOT.jar) for conscrypt at available in "ACT2-Complete\conscrypt-transportauth\libs" folder just import them as external dependency in eclipse or neatbean or set the path to these jars in FirstJar and SecondJar at line number 28 and 29 in build.gradle.

ii) A shared library is available at "conscrypt-transportauth\libs\conscrypt_openjdk_jni\shared" named "libconscrypt_openjdk_jni.so" you just need to set 
export LD_LIBRARY_PATH=<absolute path to this directory containg this .so file>. This will enable java to find this library when it attempts to load this JNI library.


2. Just run the main function of HTTPSServer class and it will listen for connacetion.

3. conscrypt-transportauthclient module is java module with gradle as build tool. The class HTTPSClient run the Transport Authentication server. This class has one dependency. Just add the same two jars as in step 1 as external dependency and run the main function of HTTPSClient class with first command line argument as 'HMAC' or 'Signature'. it will start client and send request to Server started in Step 1.

4. Read the cpmmand line output it will show Exported keying material and HTTPS requests from both client and server end.


Instruction for build whole project:
------------------------------------

This build instruction and demo is based on x64 Linux distribution.

Before you begin, you'll first need to properly configure the [Prerequisites](#Prerequisites) as
described below.


```
Prerequisites: 
-------------
Conscrypt requires that you have __Java__, __BoringSSL__ and the __Android SDK__ configured as
described below.

#### Java
The build requires that you have the `JAVA_HOME` environment variable pointing to a valid JDK.
set JAVA_HOME <path to JDK home directory>



#### Android SDK
[Download and install](https://developer.android.com/studio/install.html) the latest Android SDK
and set the `ANDROID_HOME` environment variable to point to the root of the SDK
(e.g. `export ANDROID_HOME=/usr/local/me/Android/Sdk`).
Note: if you install Android studio the SDK is also installed. Notw down its path.

#### BoringSSL
Before you can build BoringSSL, you'll first need to set up its
[prerequisites](https://boringssl.googlesource.com/boringssl/+/HEAD/BUILDING.md#Build-Prerequisites).

Follow the steps below for your platform.

##### Download
Checkout BoringSSL to a directory of your choice and then build as follows:

```bash
git clone https://boringssl.googlesource.com/boringssl
cd boringssl

# Make sure you have all dependencies of boringssl installed e.g. cmake, perl, ninja etc. Few tips also mentioned. If the cmake failed due to module not found errors.

# Also need to set an environment variable to point to the installation location.
export BORINGSSL_HOME=$PWD
```
#PWD mean main directory of boringssl code.

##### Building on Linux/OS-X
To build in the 64-bit version on a 64-bit machine:
```bash
mkdir build64
cd build64
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS=-Wa,--noexecstack \
      -GNinja ..
ninja
```

To make a 32-bit build on a 64-bit machine:
```base
mkdir build32
cd build32
cmake -DCMAKE_TOOLCHAIN_FILE=../util/32-bit-toolchain.cmake \
      -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS="-Wa,--noexecstack -m32 -msse2" \
      -GNinja ..
ninja
```

One ninja command is successful; it will build a couple of static and dynamic libraries of each package of boringssl. Verify the BORINGSSL_HOME is set.


To build the conscrypt along with two additional server and client modules, we added.


```bash
$ cd ACT2-Complete
$ ./gradlew build
```

Once build command is successful two task from java modules can be executed to run server and.

Running The Server and Client
---------------------------
runTransportAuthServer will start the server waiting for connection on port 8333 mentioned in app.config file.
It contains the name and password if ssl certificates for both client and server. The files are read from the resource directory in each module. If you want to use your own certificates make sure they are in p12 format and set their name and password in app.config in both modules. For client module you also need to provide the private key used as pem file.

Executing TransportAuthJavaClientWithHMAC Task will run the server whichbis waiting for connection.

```bash
./gradlew -t runTransportAuthServer
```

```bash
./gradlew -t runTransportAuthJavaClientWithHMAC --args='HMAC'
./gradlew -t runTransportAuthJavaClientWithHMAC --args='Signature'

```
The value of the first argument to main class can be HMAC for symmetric HMAC512 and Symmetric for asymmetric algorithms used in demo (ShA256WithRSA).


Possible issue encountered:

#openjdk_jni native library not found we need to set the library path which contains native shared libraries.
export LD_LIBRARY_PATH=./ACT2-Complete/openjdk/build/libs

#While installing android studio sdk manually licences issue may arrive
yes | tools/bin/sdkmanager  --licenses

# cmake may failed to compile due ti missing libraries
install cryptopp cryptopp-devel
sudo yum install libstdc++-static libstdc++-static.i686

