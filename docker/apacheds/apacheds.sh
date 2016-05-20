#!/bin/bash

if [ -f /bootstrap/config.ldif ] && [ ! -f /var/lib/apacheds-2.0.0-M20/default/conf/config.ldif_migrated ]; then
    echo "Using config file from /bootstrap/config.ldif"
    rm -rf /var/lib/apacheds-2.0.0-M20/default/conf/config.ldif

    cp /bootstrap/config.ldif /var/lib/apacheds-2.0.0-M20/default/conf/
    chown apacheds.apacheds /var/lib/apacheds-2.0.0-M20/default/conf/config.ldif
fi

if [ -d /bootstrap/schema ]; then
    echo "Using schema from /bootstrap/schema directory"
    rm -rf /var/lib/apacheds-2.0.0-M20/default/partitions/schema 

    cp -R /bootstrap/schema/ /var/lib/apacheds-2.0.0-M20/default/partitions/
    chown -R apacheds.apacheds /var/lib/apacheds-2.0.0-M20/default/partitions/
fi

# There should be no correct scenario in which the pid file is present at container start
rm -f /var/lib/apacheds-2.0.0-M20/default/run/apacheds-default.pid

echo "START APACHEDS"

exec "$@"



