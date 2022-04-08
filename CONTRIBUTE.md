# Welcome to GitHub docs contributing guide <!-- omit in toc -->

## Start

To begin work with this plugin you should be able to lunch crowd and jenkins instance.
In main dir of this repo there is an `./start.sh` script which will help you with this.
For now it basing on gitpod environment, but it could be tweaked quite a bit.

## Crowd

Script prepared two environments. One is our crowd instance.
Sadly there is no possibility to use any license attached to jenkins infra.
To test it please use [this url](https://developer.atlassian.com/platform/marketplace/timebomb-licenses-for-testing-server-apps/
).
Those are licenses which are expiring after some time.
One which is working for us is: `3 hour expiration for all Atlassian host products*`

When you log into crowd gui use this timebomb license, next select the easiest option - embedded data base.
At the end as source file should be one located on server. Please pass `/crowd_backup.xml` as a backup source.

### To integrate with jenkins and testing purposes:

Crowd login creds are:
user:         admin
pass:         admin

Application:
application:  jenkins
pass:         jenkins

