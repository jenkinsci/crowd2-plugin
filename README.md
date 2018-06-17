# Crowd 2 Plugin for Jenkins (crowd2-plugin)

This plugin allows using [Atlassian Crowd](https://www.atlassian.com/software/crowd) or [JIRA](https://www.atlassian.com/software/jira) as an authentication and authorization provider for Jenkins (Crowd version 2 and later). 

[![Build Status](https://ci.jenkins.io/buildStatus/icon?job=Plugins/crowd2-plugin/master)](https://ci.jenkins.io/job/Plugins/job/crowd2-plugin/job/master/)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=jenkins-crowd2-plugin&metric=coverage)](https://sonarcloud.io/dashboard?id=jenkins-crowd2-plugin)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=jenkins-crowd2-plugin&metric=security_rating)](https://sonarcloud.io/dashboard?id=jenkins-crowd2-plugin)

[![Quality Gate](https://sonarcloud.io/api/project_badges/quality_gate?project=jenkins-crowd2-plugin)](https://sonarcloud.io/dashboard?id=jenkins-crowd2-plugin)

## Usage

1. Add a new generic application in Crowd like described in the [official docs](https://confluence.atlassian.com/crowd/adding-an-application-18579591.html#AddinganApplication-UsingCrowd's'AddApplication'Wizard).
2. In Jenkins navigate to *Manage Jenkins* -> *Manage Plugins* -> *Available*, and search for "*Crowd 2 Integration*". Install this plugin.
3. In Jenkins navigate to *Manage Jenkins* -> *Configure Global Security*. Tick *Enable Security* and select *Crowd 2* as your Security Realm.
4. Insert your Crowd URL and the application credentials you created in step 1.

This plugin works well with [Matrix Authorization Strategy Plugin](https://plugins.jenkins.io/matrix-auth):
You can use Crowd users and groups to define permissions on folder/pipeline/job level.

## Development

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

```
git clone https://github.com/pingunaut/crowd2-plugin/
cd crowd2-plugin
mvn install

# to start the plugin in a local embedded test environment, run
mvn hpi:run
```

## Deployment

### Local embedded test environment

To start the plugin in a local test environment, run
```
mvn hpi:run
```

### Standalone test environment

To start a local build of the plugin in a standalone test environment, run
```
mvn install
```
then upload the resulting .hpi file (target/crowd2-VERSION.hpi) like described in the [official documentation](https://jenkins.io/doc/book/managing/plugins/#advanced-installation).

## Built With

* [Jenkins](https://jenkins.io/) - Automation server
* [Maven](https://maven.apache.org/) - Dependency Management

## Versioning

We use [SemVer](http://semver.org/) for versioning (starting from version 2.0.0). For the versions available, see the [tags on this repository](https://github.com/pingunaut/crowd2-plugin/tags). 

## Authors

See the list of [contributors](https://github.com/jenkinsci/crowd2-plugin/contributors) who participated in this project.

## Roadmap

The following changes and improvements are planned for the following releases

### 2.0.0

* add Jenkinsfile to run an automated build
* Merge open pull requests to fix caching and httpclient to solve performance and compatibility issues
* Update to latest libs
* Add some unit tests

### 3.0.0

* Improve test coverage
* Pickup changes from the refactoring branch
* Make RememberMe work
* Make SSO work

### 3.x

* Work on the open JIRA issues
 
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
