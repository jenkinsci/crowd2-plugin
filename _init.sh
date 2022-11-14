#!/bin/bash -x
MVN_SETTINGS_PATH="${HOME}/.m2/settings.xml"

# cerate folder which holds repo
mkdir -p "$(dirname "${MVN_SETTINGS_PATH}")"

# check if any mvn file is created
if [[ -f "${MVN_SETTINGS_PATH}" ]]; then
    BACKUP_DATE="$(date +%s)"
    mv "${MVN_SETTINGS_PATH}" "${MVN_SETTINGS_PATH}.bak${BACKUP_DATE}"
fi

if [[ -n "${ARTIFACTORY_PASS}" ]]; then
    echo "Please define variable ARTIFACTORY_PASS"
    exit 1
fi

if [[ -n "${ARTIFACTORY_USER}" ]]; then
    echo "Please define variable ARTIFACTORY_USER"
    exit 1
fi

# get settings.xml form jenkins
curl -u "${ARTIFACTORY_USER}:${ARTIFACTORY_PASS}" https://repo.jenkins-ci.org/setup/settings.xml > "${MVN_SETTINGS_PATH}"
