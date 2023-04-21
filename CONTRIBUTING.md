# Welcome to Crowd2 Jenkins Plugins docs contributing guide <!-- omit in toc -->

Nice to see you, and thank you for your time to contribute to the Jenkins community.
This document's purpose is to make it as seamless as possible.

## Start

To begin working with this plugin, you should be able to lunch crowd and Jenkins instance.
In the main directory of this repo there is a ```./start.sh``` script which will help you with this.
For now, it is based on the Gitpod environment, but it could work on others, but some tweaks will be required.

### Build Image

If you pass in script `start.sh` java version number as an argument, you can build an image with a different java version. Possible values: [11, 17]

``` sh
./start.sh 11
```

## Crowd

The script is preparing two environments. One of them is for crowd instance.
Sadly, there is no possibility to use any license attached to Jenkins infrastructure.
To test it, please consider using [this URL](https://developer.atlassian.com/platform/marketplace/timebomb-licenses-for-testing-server-apps/
).
Those are licenses which are expiring after some time.
One which is working for us is: `3 hour expiration for all Atlassian host products*`

When you log into crowd GUI, use this timebomb license.
Next select `embedded database`.
When your database will be ready, go to the next page and select to load from backup.
Backup file should be already placed on the server. Please pass `/crowd_backup.xml` as a backup source.

### To integrate with Jenkins and testing purposes:

Crowd login credentials are:
* user:         admin
* pass:         admin

Application:
* application:  jenkins
* pass:         jenkins
