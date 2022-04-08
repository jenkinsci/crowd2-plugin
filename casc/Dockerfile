FROM jenkins/jenkins:2.289.1

# expect a build-time variable
ARG GITPOD_WORKSPACE_CLUSTER_HOST \
    HOSTNAME
# use the value to set the ENV var default
ENV GITPOD_WORKSPACE_CLUSTER_HOST=$GITPOD_WORKSPACE_CLUSTER_HOST \
    HOSTNAME=$HOSTNAME

# add configuration of jenkins casc to test instance
# ENV     CASC_JENKINS_CONFIG_DIR="/var/jenkins_home/custom_casc_config"
# ENV     CASC_JENKINS_CONFIG="${CASC_JENKINS_CONFIG_DIR}/jenkins.yaml"
# RUN     mkdir -p "${CASC_JENKINS_CONFIG_DIR}"
# COPY    --chown=jenkins:jenkins "casc/jenkins.yml" "${CASC_JENKINS_CONFIG}"

# install builded plugin and add dependencies
COPY    --chown=jenkins:jenkins target/crowd2.hpi /usr/share/jenkins/ref/plugins/
RUN     jenkins-plugin-cli --plugins configuration-as-code \
                                     apache-httpcomponents-client-4-api \
                                     mailer
RUN printenv | sort
