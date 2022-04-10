# expect a build-time variable
ARG JAVA_VERSION
ARG JENKINS_SITE_NAME

FROM jenkins/jenkins:2.289.1-jdk$JAVA_VERSION

# use the value to set the ENV var default
ENV JENKINS_SITE_NAME=$JENKINS_SITE_NAME
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

# use correct user
USER jenkins

# add copy all secrets
COPY    --chown=jenkins:jenkins "casc/jenkins_home" "/var/jenkins_home"

# add configuration of jenkins casc to test instance
ENV     CASC_JENKINS_CONFIG_DIR="/var/jenkins_home/custom_casc_config"
ENV     CASC_JENKINS_CONFIG="${CASC_JENKINS_CONFIG_DIR}/jenkins.yml"
RUN     mkdir -p "${CASC_JENKINS_CONFIG_DIR}"
COPY    --chown=jenkins:jenkins "casc/jenkins.yml" "${CASC_JENKINS_CONFIG}"

# install builded plugin and add dependencies
COPY    --chown=jenkins:jenkins target/crowd2.hpi /usr/share/jenkins/ref/plugins/
RUN     jenkins-plugin-cli --plugins configuration-as-code \
                                     apache-httpcomponents-client-4-api \
                                     mailer
RUN printenv | sort
