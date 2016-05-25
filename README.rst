==========
plone.auth
==========

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

Credits
=======

from Iskra Desenvolupament SCCL:

- Ramon Navarro Bosch
- Aleix Llusà

