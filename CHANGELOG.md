
# Version History

## Newer one can be found on [github](https://github.com/jenkinsci/crowd2-plugin/releases)

## Version 2.0.1 (Sep 25, 2018)

-   Fix security issues:
    [one](https://jenkins.io/security/advisory/2018-09-25/#SECURITY-1067),
    [two](https://jenkins.io/security/advisory/2018-09-25/#SECURITY-1068)

## Version 2.0.0 (Jul 23, 2018) 

Fixed Bugs

-   [JENKINS-16703](https://issues.jenkins-ci.org/browse/JENKINS-16703) -
    Too many periodic requests to Crowd server
-   [JENKINS-27070](https://issues.jenkins-ci.org/browse/JENKINS-27070) -
    Plenty of "SEVERE: Host connection pool not found,
    hostConfig=HostConfiguration"

Improvements

-   [JENKINS-40472](https://issues.jenkins-ci.org/browse/JENKINS-40472) -
    Crowd2 plugin should allow blanks in parameter 'Restrict groups'
-   Added possibility to enable caching to reduce remote calls to Crowd

Thanks a lot [Arnaud
Héritier](https://wiki.jenkins.io/display/~aheritier), [Unknown User
(gmshake)](https://wiki.jenkins.io/display/~gmshake) and all others who
tested, gave input and had patience
![](https://assets-cdn.github.com/images/icons/emoji/unicode/1f44d.png){width="20"
height="20"}

## Version 1.8 (Aug 1, 2014)

-   \[JENKINS-23208\] Fixed trace with enabled "remember me" checkbox.
-   isAuthenticated() in /whoAmI page is now true.

## Version 1.7 (Apr 23, 2014)

-   \[JENKINS-21852\] Added http proxy configuration.
-   \[JENKINS-18791\] Session validation interval saved from ui.
-   \[JENKINS-13279\] Don't use ssoTokenHelper, work with Embedded Crowd
    in Jira.
-   \[JENKINS-16703\] More options for connection configuration.
-   Updated rest-api library to 2.7.1

## Version 1.6 (Nov 23, 2013)

Note: **check that your group list uses CSV separator and you have SSO
checkbox enabled (if you use it).**

-   [pull \#3](https://github.com/jenkinsci/crowd2-plugin/pull/3) Fixed
    bug whereby bogus user IDs were created that included display names.
    **When upgrading, manual cleanup of** `$JENKINS_HOME/users/` **may
    be required.**
-   [JENKINS-15509](https://issues.jenkins-ci.org/browse/JENKINS-15509):
    Don't require group.
-   [JENKINS-15753](https://issues.jenkins-ci.org/browse/JENKINS-15753):
    Allow spaces in group names.
-   [JENKINS-19212](https://issues.jenkins-ci.org/browse/JENKINS-19212):
    Make "useSSO" optional.
-   Updated rest-api library to 2.6.6.

## Version 1.5 (Aug 23, 2012)

-   [JENKINS-11829](https://issues.jenkins-ci.org/browse/JENKINS-11829):
    Support more than one group
-   [JENKINS-12339](https://issues.jenkins-ci.org/browse/JENKINS-12339):
    misspelling in error message
-   [JENKINS-13547](https://issues.jenkins-ci.org/browse/JENKINS-13547):
    Jenkins runs extremely slow with remote crowd server

## Version 1.4 (Nov 25, 2011)

-   Upgrade commons-httpclient version to 3.1.

## Version 1.3 (Oct 27, 2011)

Fixed the following bugs:

-   [JENKINS-11418](https://issues.jenkins-ci.org/browse/JENKINS-11418):
    Crowd2 doesn't always show full user name
-   [JENKINS-11507](https://issues.jenkins-ci.org/browse/JENKINS-11507):
    Single-sign-on isn't working correctly in the Crowd 2 plugin

## Version 1.2 (Oct 19, 2011)

-   Fixed a problem that prevented you at least from adding pre- or post
    build steps when reconfiguring a build job.
-   Added some debug log messages.

## Version 1.1 (Oct 11, 2011)

-   Fix for a problem that I discovered in combination with the
    [Email-ext
    plugin](https://wiki.jenkins.io/display/JENKINS/Email-ext+plugin):
    Sending emails to the logged-in user was not possible because a
    lookup operation in the Crowd server for details about a user
    failed.
-   The Crowd user Id is now shown besides the display name of the
    logged-in user.
-   Added more debug log messages.

    The debug log messages are usually not shown in Jenkins' console
    output because they are logged with log level FINE or below. See
    [here](https://wiki.jenkins.io/display/JENKINS/Logging) how to enable
    them (the plugin uses logger classes `de.theit.jenkins.crowd.XXX`).

## Version 1.0 (Sep 23, 2011)

-   Initial release