#!/bin/sh -ex
#
# This requires a Conscrypt build from the MASQUE branch, e.g.
# https://gitlab.com/eighthave/conscrypt/-/jobs/2184223295

binary_dir=conscrypt_test_MASQUE_32c95faadad035dfe85297f3098b7b1f20cf14c1/openjdk/build/libs
conscrypt_jar=${binary_dir}/conscrypt-openjdk-2.6.masque1646856796.job2184223295-linux-x86_64.jar

algorithm=HMAC
if [ -n "$1" ]; then
    algorithm=$1
fi

javac -h conscrypt-transportauthclient/src/main/java/  -classpath .:${conscrypt_jar} \
      conscrypt-transportauthclient/src/main/java/com/example/conscrypt_transportauthclient/HTTPSClient.java


java \
    -Djava.library.path=$binary_dir/conscrypt_openjdk_jni/shared \
    -classpath .:conscrypt-transportauthclient/src/main/java:${conscrypt_jar} \
    com.example.conscrypt_transportauthclient.HTTPSClient \
    $algorithm \
    `pwd`/conscrypt-transportauthclient/src/main/resources/config.properties
