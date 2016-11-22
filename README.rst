[![Build Status](https://travis-ci.org/pyrenees/plone.oauth.svg?branch=master)](https://travis-ci.org/pyrenees/plone.oauth)

plone.oauth
===========

Install & Run
=============

Docker::

 docker-compose -f docker-compose.yml up

Then available at::

 http://<docker-host>:6543


This default port can be changed in `docker-compose.yml`, e.g. change to 3456::

 - "6543:6543"
 + "3456:6543"


Default configuration
=====================

Superuser
---------

* admin@example.com admin

Test user
---------

* user@example.com user

Clients
-------

* plone plone


Testing
=======

Needs an ApacheDS + Redis environment::

 docker-compose -f docker-compose-dev.yml up
 ldapmodify -h <docker-host> -p 10389 -D 'uid=admin,ou=system' -w secret -f ./ldap-bootstrap/demo.ldif

Then it can be tested::

 ./bin/py.test --ldap <docker-host> --ldap-port 10389 --redis <docker-host> --redis-port 6379


Extending plone.oauth from another Pyramid Application
======================================================

Copy `development.ini` and `production.ini` configuration files. Note that you will need ldap and redis services such as the ones configured in `docker-compose.yml`.

Include the configuration from plone.oauth into your new application::

 config.include('plone.oauth')


See http://docs.pylonsproject.org/projects/pyramid/en/1.7-branch/narr/extending.html



Credits
=======

from Iskra Desenvolupament SCCL:

- Ramon Navarro Bosch
- Aleix Llusà

from Atlasense:

- Daniel Manchón Vizuete
