# expect a build-time variable
ARG JAVA_VERSION
ARG JENKINS_SITE_NAME

FROM jenkins/jenkins:2.401.3-jdk$JAVA_VERSION

# use the value to set the ENV var default
ENV JENKINS_SITE_NAME=$JENKINS_SITE_NAME
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG="/var/jenkins_home/casc_config/jenkins.yml"

# use correct user
USER jenkins

# add copy all secrets
COPY    --chown=jenkins:jenkins "casc/jenkins_home" "/var/jenkins_home"

# install builded plugin and add dependencies
RUN     jenkins-plugin-cli --plugins configuration-as-code \
                                     apache-httpcomponents-client-4-api \
                                     mailer \
                                     monitoring \
                                     jaxb

COPY    --chown=jenkins:jenkins target/crowd2.hpi /usr/share/jenkins/ref/plugins/crowd2.hpi.override
