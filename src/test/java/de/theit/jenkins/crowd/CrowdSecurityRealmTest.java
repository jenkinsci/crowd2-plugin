package de.theit.jenkins.crowd;

import de.theit.jenkins.crowd.CrowdSecurityRealm.CacheConfiguration;

import hudson.util.Secret;

import org.assertj.core.api.Assertions;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class CrowdSecurityRealmTest {

    // Needed for getDescriptor().save() in the compatibility constructor
    @Rule public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void testCrowdSecurityRealmConstructorWithTypicalData() {
        String url = "https://crowd2/";
        String applicationName = "Jenkins";
        Secret password = Secret.fromString("crowd_password");
        String group = "restricted_users";
        boolean nestedGroups = true;
        int sessionValidationInterval = 2;
        boolean useSSO = true;
        String cookieDomain = "cookie_domain";
        String cookieTokenkey = "token_key";
        boolean useProxy = true;
        String httpProxyHost = "proxy_host";
        String httpProxyPort = "8080";
        String httpProxyUsername = "proxy_user";
        Secret httpProxyPassword = Secret.fromString("proxy_password");
        String socketTimeout = "20000";
        String httpTimeout = "5000";
        String httpMaxConnections = "20";
        CacheConfiguration cache = new CacheConfiguration(20, 300);
        CrowdSecurityRealm realm = new CrowdSecurityRealm(
            url,
            applicationName,
            password,
            group,
            nestedGroups,
            sessionValidationInterval,
            useSSO,
            cookieDomain,
            cookieTokenkey,
            useProxy,
            httpProxyHost,
            httpProxyPort,
            httpProxyUsername,
            httpProxyPassword,
            socketTimeout,
            httpTimeout,
            httpMaxConnections,
            cache);

        Assertions.assertThat(realm.getCacheSize()).isEqualTo(20);
        Assertions.assertThat(realm.getCacheTTL()).isEqualTo(300);
    }

    @Test
    public void testCrowdSecurityRealmConstructorWithNullData() {
        String url = null;
        String applicationName = null;
        Secret password = null;
        String group = null;
        boolean nestedGroups = false;
        int sessionValidationInterval = 0;
        boolean useSSO = false;
        String cookieDomain = null;
        String cookieTokenkey = null;
        boolean useProxy = false;
        String httpProxyHost = null;
        String httpProxyPort = null;
        String httpProxyUsername = null;
        Secret httpProxyPassword = null;
        String socketTimeout = null;
        String httpTimeout = null;
        String httpMaxConnections = null;
        CacheConfiguration cache = null;
        CrowdSecurityRealm realm = new CrowdSecurityRealm(
            url,
            applicationName,
            password,
            group,
            nestedGroups,
            sessionValidationInterval,
            useSSO,
            cookieDomain,
            cookieTokenkey,
            useProxy,
            httpProxyHost,
            httpProxyPort,
            httpProxyUsername,
            httpProxyPassword,
            socketTimeout,
            httpTimeout,
            httpMaxConnections,
            cache);

        Assertions.assertThat(realm.getCacheSize()).isNull();
        Assertions.assertThat(realm.getCacheTTL()).isNull();
    }

    @Test
    public void testCrowdSecurityRealmDeprecatedConstructorWithNullData() {
        String url = null;
        String applicationName = null;
        String password = null;
        String group = null;
        boolean nestedGroups = false;
        int sessionValidationInterval = 0;
        boolean useSSO = false;
        String cookieDomain = null;
        String cookieTokenkey = null;
        boolean useProxy = false;
        String httpProxyHost = null;
        String httpProxyPort = null;
        String httpProxyUsername = null;
        String httpProxyPassword = null;
        String socketTimeout = null;
        String httpTimeout = null;
        String httpMaxConnections = null;
        CrowdSecurityRealm realm = new CrowdSecurityRealm(
            url,
            applicationName,
            password,
            group,
            nestedGroups,
            sessionValidationInterval,
            useSSO,
            cookieDomain,
            cookieTokenkey,
            useProxy,
            httpProxyHost,
            httpProxyPort,
            httpProxyUsername,
            httpProxyPassword,
            socketTimeout,
            httpTimeout,
            httpMaxConnections);

        Assertions.assertThat(realm.getCacheSize()).isNull();
        Assertions.assertThat(realm.getCacheTTL()).isNull();
    }

}
