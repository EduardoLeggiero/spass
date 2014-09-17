'use strict'

define(['angular'], (angular) ->

  web = angular.module('web', ['ngResource', 'ngRoute'])

  web.directive 'spassInput', ->
    restrict: 'E'
    replace: 'true'
    scope:
      name: '@'
      model: '='
      label: '@'
      placeholder: '@'
      size: '@'
      type: '@'
      value: '@'
      required: '@'
      errors: "="
    templateUrl: 'web/vassets/partials/input.tpl.html'

  web.directive 'spassForm', ->
    restrict: 'E'
    scope:
      controller: '='
      submit: '='

  web.directive 'spassSubmit', ->
    restrict: 'E'
    scope:
      class: '@'
      value: '@'
    templateUrl: 'web/vassets/partials/submit.tpl.html'

  web.directive 'spassButton', ->
    restrict: 'E'
    scope:
      click: '@'
      value: '@'
    templateUrl: 'web/vassets/partials/button.tpl.html'

  web.directive 'spassHeader', ->
    restrict: 'E'
    scope:
      h1: '@'
      h2: '@'
      lead: '@'
      subtext: '@'
      navModule: '@'
      navService: '@'
    templateUrl: 'web/vassets/partials/header.tpl.html'
    transclude: true

  web.directive 'spassNav', ->
    restrict: 'E'
    scope:
      module: '@'
      service: '@'
    templateUrl: 'web/vassets/partials/navigation.tpl.html'
    link: ($scope) ->
      $scope.data = angular.injector([$scope.module]).get($scope.service).get(() -> $scope.$apply())
)