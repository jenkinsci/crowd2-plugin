#!/bin/bash
# https://www.baeldung.com/maven-clear-cache


mvn dependency:purge-local-repository -DactTransitively=false -DreResolve=false
rm -rf target