# Changelog

## 0.0.1

### 2014-09-29
    Replaced BoneCP with HikariCP as the connecton pool
    Fixed the store authenticator
    Still have issues when changing the password

### 2014-09-16
    Renamed project to Slick Play AngularJS SecureSocial Seed (SPASS)
    Upgraded SecureSocial to 3.0-M1
    Removed SORM and db module
    Converted everything to Slick 2.1 and using Play's built in Slick support
    Project now uses scala 2.11 and sbt 13.5

### 2014-07-20
    Upgraded to use Play 2.3.1 ***SecureSocial is broken until verion 3 supporting Play 2.3.1**
    Renamed common module to web
    Moved all root level routing and pages to the parent project
    Added activator 1.2.3 wrapper to the build

### 2014-03-05
    Added initial support for Slick
    Fixed SecureSocial config
    Added templates
    Added AngularJS directives

### 2014-02-23
    Added WebJars library dependencies
    Now using RequireJS for AMD

### 2014-02-06
    DB support is now a plugin
    Subprojects

### 2014-01-30
    First pure AngularJS build
    Removed play-template project

### 2014-01-24
    Split the project into multiple modules
    Removed play-template project

### 2014-01-21
    Converted most screens to use AngularJS instead of full page reloads
