#!/bin/sh -ex
#
# This requires a Conscrypt build from the MASQUE branch, e.g.
# https://gitlab.com/eighthave/conscrypt/-/jobs/2184223295

binary_dir=conscrypt_test_MASQUE_32c95faadad035dfe85297f3098b7b1f20cf14c1/openjdk/build/libs
conscrypt_jar=${binary_dir}/conscrypt-openjdk-2.6.masque1646856796.job2184223295-linux-x86_64.jar

javac -h conscrypt-transportauth/src/main/java/ -classpath .:${conscrypt_jar} \
      conscrypt-transportauth/src/main/java/com/example/conscrypt_transportauth/FileResourcesUtils.java \
      conscrypt-transportauth/src/main/java/com/example/conscrypt_transportauth/HTTPSServer.java

java \
    -Djava.library.path=$binary_dir/conscrypt_openjdk_jni/shared \
    -classpath .:conscrypt-transportauth/src/main/java:${conscrypt_jar} \
    com.example.conscrypt_transportauth.HTTPSServer \
    `pwd`/conscrypt-transportauth/src/main/resources/config.properties

