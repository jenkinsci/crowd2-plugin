# Crowd 2 Plugin for Jenkins (crowd2-plugin)

This plugin allows using [Atlassian Crowd](https://www.atlassian.com/software/crowd) as an authentication and authorization provider for Jenkins (Crowd version 2 and later). 

[![Build Status](https://ci.jenkins.io/buildStatus/icon?job=Plugins/crowd2-plugin/master)](https://ci.jenkins.io/job/Plugins/job/crowd2-plugin/job/master/)

## Usage
//TODO: describe usage and add some screenshots or gifs


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

We use [SemVer](http://semver.org/) for versioning (starting from version 1.9.0). For the versions available, see the [tags on this repository](https://github.com/pingunaut/crowd2-plugin/tags). 

## Authors

See the list of [contributors](https://github.com/jenkinsci/crowd2-plugin/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
