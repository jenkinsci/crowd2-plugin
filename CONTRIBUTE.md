# Welcome to Crowd2 Jenkins Plugins docs contributing guide <!-- omit in toc -->

nice to see you and thank you for your time to contribute to the Jenkins community.
This document purpose is to make it as seamless as possible.

## Start

To begin work with this plugin you should be able to lunch crowd and jenkins instance.
In main directory of this repo there is an ```./start.sh``` script which will help you with this.
For now it base on gitpod environment, but it could work on others, but some tweaks will be required.

### Build img

If you pass to `start.sh` java version number as argument you can build img with different java version. Possible values: [8, 11, 17]
```
./start.sh 11
```


## Crowd

Script is preparing two environments. One of them is for crowd instance.
Sadly there is no possibility to use any license attached to jenkins infra.
To test it please use [this url](https://developer.atlassian.com/platform/marketplace/timebomb-licenses-for-testing-server-apps/
).
Those are licenses which are expiring after some time.
One which is working for us is: `3 hour expiration for all Atlassian host products*`

When you log into crowd gui use this timebomb license. 
Next select `embedded database`.
When your database will be ready, go to next page and select to load from backup.
Backup file should be already placed on server. Please pass `/crowd_backup.xml` as a backup source.

### To integrate with jenkins and testing purposes:

Crowd login credentials are:
* user:         admin
* pass:         admin

Application:
* application:  jenkins
* pass:         jenkins
