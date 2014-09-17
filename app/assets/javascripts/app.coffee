'use strict'

requirejs.config(
  paths:
    'angular': ['../lib/angularjs/angular'],
    'angular-resource': ['../lib/angularjs/angular-resource'],
    'angular-route': ['../lib/angularjs/angular-route']
  shim:
    'angular':
      exports: 'angular'
    'angular-route': ['angular'],
    'angular-resource': ['angular']
)

require([
    'angular',
    'angular-resource',
    'angular-route',
    '/vassets/javascripts/web/main.js',
    '/vassets/javascripts/users/main.js'
  ], (angular) ->

  spass = angular.module('spass', ['ngResource', 'ngRoute', 'web', 'users'])

  spass.factory 'navigation',
  ($resource) ->
    $resource('navigation')

  spass.config [
    '$routeProvider',
    ($routeProvider) ->
      $routeProvider.when '/',
        templateUrl: 'users/vassets/partials/signup-start.tpl.html'
      $routeProvider.otherwise
        redirectTo: '/'
  ]

  angular.bootstrap(document, ['spass']);
)