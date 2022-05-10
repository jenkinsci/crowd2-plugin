#!/bin/bash
MVN_SETTINGS_PATH="$HOME/.m2/settings.xml"

# cerate folder which holds repo
mkdir -p "$(dirname $MVN_SETTINGS_PATH)"

# check if any mvn file is created
if [ -f "$MVN_SETTINGS_PATH" ]; then
    mv "$MVN_SETTINGS_PATH" "$MVN_SETTINGS_PATH.bak"
fi

# move our file as a main one for mvn
cp -a "init/settings.xml" "$MVN_SETTINGS_PATH"


