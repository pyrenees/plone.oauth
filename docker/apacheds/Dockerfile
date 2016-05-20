FROM java:8

MAINTAINER "Ramon Navarro Bosch r.navarro@iskra.cat"

ADD apacheds.sh /usr/local/bin/ 

RUN apt-get update \
    && apt-get install -y apt-utils \
    && apt-get install -y ldap-utils \
    && curl -s http://apache.rediris.es/directory/apacheds/dist/2.0.0-M20/apacheds-2.0.0-M20-amd64.deb -o /tmp/apacheds.deb \
    && dpkg -i /tmp/apacheds.deb \
    && rm -rf /tmp/apacheds.deb \
    && mkdir -p /bootstrap \
    && ln -s /var/lib/apacheds-2.0.0-M20/default/partitions /data \
    && chmod +x /usr/local/bin/apacheds.sh \
    && chown -R apacheds.apacheds /data \
    && chown -R apacheds.apacheds /var/lib/apacheds-2.0.0-M20/default/partitions


VOLUME /data
VOLUME /bootstrap

EXPOSE 10389
EXPOSE 389

ENTRYPOINT ["/usr/local/bin/apacheds.sh"]

CMD ["/opt/apacheds-2.0.0-M20/bin/apacheds", "console", "default"]