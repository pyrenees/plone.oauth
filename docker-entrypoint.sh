#!/bin/bash
set -e

if [ -n "$REDIS_PORT_6379_TCP_ADDR" ]; then
    if [ -z "$REDIS_DB_HOST" ]; then
        REDIS_DB_HOST='redis'
    else
        echo >&2 'warning: both REDIS_DB_HOST and REDIS_PORT_6379_TCP_ADDR found'
        echo >&2 "  Connecting to REDIS_DB_HOST ($REDIS_DB_HOST)"
        echo >&2 '  instead of the linked redis container'
    fi
fi

if [ -n "$REDIS_PORT_6379_TCP_PORT" ]; then
    if [ -z "$REDIS_DB_PORT" ]; then
        REDIS_DB_PORT=6379
    else
        echo >&2 'warning: both REDIS_DB_PORT and REDIS_PORT_6379_TCP_PORT found'
        echo >&2 "  Connecting to REDIS_DB_PORT ($REDIS_DB_PORT)"
        echo >&2 '  instead of the linked redis container'
    fi
fi

if [ -n "$LDAP_PORT_10389_TCP_ADDR" ]; then
    if [ -z "$LDAP_DB_HOST" ]; then
        LDAP_DB_HOST='ldap'
    else
        echo >&2 'warning: both LDAP_HOST and LDAP_PORT_10389_TCP_ADDR found'
        echo >&2 "  Connecting to LDAP_HOST ($LDAP_HOST)"
        echo >&2 '  instead of the linked ldap container'
    fi
fi

if [ -n "$LDAP_PORT_10389_TCP_PORT" ]; then
    if [ -z "$LDAP_DB_PORT" ]; then
        LDAP_DB_PORT=10389
    else
        echo >&2 'warning: both LDAP_DB_PORT and LDAP_PORT_10389_TCP_PORT found'
        echo >&2 "  Connecting to LDAP_DB_PORT ($LDAP_DB_PORT)"
        echo >&2 '  instead of the linked ldap container'
    fi
fi

if [ -z "$LDAP_DB_HOST" ]; then
    echo >&2 'error: missing LDAP_DB_HOST'
    echo >&2 '  Did you forget to --link some_ldap_container:ldap or set an external db'
    echo >&2 '  with -e LDAP_DB_HOST=hostname'
    exit 1
fi

if [ -z "$LDAP_DB_PORT" ]; then
    echo >&2 'error: missing LDAP_DB_PORT'
    echo >&2 '  Did you forget to --link some_ldap_container:ldap or set an external db'
    echo >&2 '  with -e LDAP_DB_PORT=hostname'
    exit 1
fi

if [ -z "$REDIS_DB_PORT" ]; then
    echo >&2 'error: missing REDIS_DB_PORT'
    echo >&2 '  Did you forget to --link some_redis_container:redis or set an external db'
    echo >&2 '  with -e REDIS_DB_PORT=port'
    exit 1
fi

if [ -z "$REDIS_DB_HOST" ]; then
    echo >&2 'error: missing REDIS_DB_HOST'
    echo >&2 '  Did you forget to --link some_redis_container:redis or set an external db'
    echo >&2 '  with -e REDIS_DB_HOST=hostname'
    exit 1
fi


if [ -z "$JWTSECRET" ]; then
    echo >&2 'error: missing required JWTSECRET environment variable'
    echo >&2 '  Did you forget to -e JWTSECRET=... ?'
    echo >&2
    exit 1
fi

if [ -z "$RAVENDSN" ]; then
    RAVENDSN=''
    echo >&2 'warning: missing required RAVENDSN environment variable'
    echo >&2 '  Did you forget to -e RAVENDSN=... ?'
    echo >&2 '  Using none raven'
    echo >&2
fi

if [ -z "$HORUS_PORT" ]; then
    HORUS_PORT=6543
    echo >&2 'warning: missing required HORUS_PORT environment variable'
    echo >&2 '  Did you forget to -e HORUS_PORT=... ?'
    echo >&2 '  Using 6543'
    echo >&2
fi

if [ -z "$LDAP_ROOT_DN" ]; then
    LDAP_ROOT_DN=''
    echo >&2 'warning: missing required LDAP_ROOT_DN environment variable'
    echo >&2 '  Did you forget to -e LDAP_ROOT_DN=... ?'
    echo >&2 '  Using none'
    echo >&2
fi

if [ -z "$LDAP_ROOT_PW" ]; then
    LDAP_ROOT_PW=''
    echo >&2 'warning: missing required LDAP_ROOT_PW environment variable'
    echo >&2 '  Did you forget to -e LDAP_ROOT_PW=... ?'
    echo >&2 '  Using none'
    echo >&2
fi


if [ -z "$LDAP_BASE_DN" ]; then
    LDAP_BASE_DN=''
    echo >&2 'warning: missing required LDAP_BASE_DN environment variable'
    echo >&2 '  Did you forget to -e LDAP_BASE_DN=... ?'
    echo >&2 '  Using none'
    echo >&2
fi

if [ -z "$LDAP_PROFILE" ]; then
    LDAP_PROFILE=''
    echo >&2 'warning: missing required LDAP_PROFILE environment variable'
    echo >&2 '  Did you forget to -e LDAP_PROFILE=... ?'
    echo >&2 '  example: ["person", "inetOrgPerson"]'
    echo >&2
    exit 1
fi

if [ -z "$LDAP_USER_FILTER" ]; then
    LDAP_USER_FILTER=''
    echo >&2 'warning: missing required LDAP_USER_FILTER environment variable'
    echo >&2 '  Did you forget to -e LDAP_USER_FILTER=... ?'
    echo >&2 '  example: mail={username},ou=Users,dc=example,dc=com'
    echo >&2
    exit 1
fi

if [ -z "$HORUS_DEBUG" ]; then
    HORUS_DEBUG='False'
    echo >&2 'warning: missing required HORUS_DEBUG environment variable'
    echo >&2 '  Did you forget to -e HORUS_DEBUG="True|False" ?'
    echo >&2 '  Using False'
    echo >&2
fi

set_config() {
    echo "SET VAR"
    echo $1
    echo $2
    key="$1"
    value="$2"
    sed -i "s%$key%$value%g" /app/production.ini
}

echo "SET CONFIG"
set_config \$JWTSECRET $JWTSECRET
set_config \$REDIS_DB_HOST $REDIS_DB_HOST
set_config \$REDIS_DB_PORT $REDIS_DB_PORT
set_config \$LDAP_HOST $LDAP_DB_HOST
set_config \$LDAP_PORT $LDAP_DB_PORT
set_config \$RAVENDSN $RAVENDSN
set_config \$HORUS_PORT $HORUS_PORT
set_config \$LDAP_ROOT_DN $LDAP_ROOT_DN
set_config \$LDAP_ROOT_PW $LDAP_ROOT_PW
set_config \$LDAP_PROFILE $LDAP_PROFILE
set_config \$LDAP_USER_FILTER $LDAP_USER_FILTER
set_config \$LDAP_BASE_DN $LDAP_BASE_DN
set_config \$HORUS_DEBUG $HORUS_DEBUG


until nc -z $LDAP_DB_HOST $LDAP_DB_PORT;
do
  echo "Waiting for ldap"
  sleep 1
done

echo "START HORUS"

exec "$@"