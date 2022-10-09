#!/bin/bash -x
CROWD_SNAPSHOT_FILE_PATH='target/crowd2.hpi'

export GITPOD_SITE="${HOSTNAME}.${GITPOD_WORKSPACE_CLUSTER_HOST}"
export JENKINS_URL="https://$JENKINS_SITE_NAME/"
export JENKINS_SITE_NAME="8080-${GITPOD_SITE}"

export CROWD_SITE_NAME="8095-${GITPOD_SITE}"
export CROWD_BACKUP_FILE="casc/crowd_backup.xml"

if [[ ! -f "$CROWD_SNAPSHOT_FILE_PATH" ]]; then
    echo "--- No builds found - building plugin ---"
    mvn -ntp clean verify
fi

# create new img with crowd2-snapshot file installed
# if there is args passed use java 11 
if [[ $# -gt 0 ]] || ! docker image inspect casc_jenkins:latest &> /dev/null; then
    echo "--- Build Docker img ---"
    export JAVA_VERSION="${1:-11}"
    docker-compose -f casc/docker-compose.yml build
fi

# fetch all needed images (crowd and jenkins one)
docker-compose -f casc/docker-compose.yml pull

echo '--- Start docker services ---'
docker-compose -f casc/docker-compose.yml up -d --remove-orphans

# TODO: Remove those comments after confirmation that this setup is also working localy
# replace crowd address to current one
# sed -i "s/http:\/\/.*\/crowd/http:\/\/$CROWD_SITE_NAME\/crowd/" "$CROWD_BACKUP_FILE"
# replace jenkins address to current one
# sed -i "s/https:\/\/\(\w\|\-\|\.\)\+\//https:\/\/$JENKINS_SITE_NAME/" "$CROWD_BACKUP_FILE"

# add crowd backup to instance
# TODO: Move to dockerfile
echo '--- Install backup file on crowdcontainer ---'
docker cp "$CROWD_BACKUP_FILE" crowd:"/crowd_backup.xml"
docker exec -it crowd chown -R crowd:crowd "/crowd_backup.xml"

echo "Now please setup database according to your preferences"
