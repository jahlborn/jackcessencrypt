#!/bin/sh

COMPAT_CLASSPATH="../../target/jackcess-encrypt-3.0.1.mods-SNAPSHOT.jar:bcprov-jdk15-1.45.jar:jackcess-3.0.0.jar:commons-logging-1.1.1.jar:commons-lang3-3.10.jar"

javac -cp $COMPAT_CLASSPATH com/healthmarketscience/jackcess/crypt/util/RC4EngineLegacy.java

cp com/healthmarketscience/jackcess/crypt/util/*.class ../main/resources/com/healthmarketscience/jackcess/crypt/util
