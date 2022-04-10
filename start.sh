#!/bin/bash
export GITPOD_SITE="${HOSTNAME}.${GITPOD_WORKSPACE_CLUSTER_HOST}"
export JENKINS_SITE_NAME="8080-${GITPOD_SITE}"
export CROWD_SITE_NAME="8095-${GITPOD_SITE}"

export JENKINS_URL="https://$JENKINS_SITE_NAME/"
export CROWD_BACKUP_FILE="./casc/crowd_backup.xml"

# create new img 
if [ $# -gt 0 ]; then
    docker-compose -f casc/docker-compose.yml build
fi

# start docker services
docker-compose -f casc/docker-compose.yml up -d --remove-orphans

# replace crowd address to current one
# sed -i "s/http:\/\/.*\/crowd/http:\/\/$CROWD_SITE_NAME\/crowd/" "$CROWD_BACKUP_FILE"
# replace jenkins address to current one
# sed -i "s/https:\/\/\(\w\|\-\|\.\)\+\//https:\/\/$JENKINS_SITE_NAME/" "$CROWD_BACKUP_FILE"
# add crowd backup to instance
docker cp "$CROWD_BACKUP_FILE" crowd:"/crowd_backup.xml"
docker exec -it crowd chown -R crowd:crowd "/crowd_backup.xml"

echo "Now please setup database according to your preferences"
