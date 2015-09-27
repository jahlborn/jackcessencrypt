#!/bin/sh

COMPAT_CLASSPATH="../../target/jackcess-encrypt-2.1.1-SNAPSHOT.jar:bcprov-jdk15-1.45.jar:jackcess-2.1.0.jar:commons-logging-1.1.1.jar:commons-lang-2.6.jar"

javac -cp $COMPAT_CLASSPATH com/healthmarketscience/jackcess/util/RC4EngineLegacy.java

cp com/healthmarketscience/jackcess/util/*.class ../main/resources/com/healthmarketscience/jackcess/util
