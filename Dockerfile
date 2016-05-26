FROM python:3.5-slim
MAINTAINER Ramon Navarro Bosch

# Update packages
RUN apt-get update -y

# Install Python Setuptools
RUN apt-get install -y libldap-dev libsasl2-dev locales git-core gcc netcat

RUN mkdir /app

# Bundle app source
ADD . /app

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

# Install buildout
RUN cd /app; python3.5 bootstrap.py

# Run buildout
RUN cd /app; ./bin/buildout -vvv

# Expose
EXPOSE  6543

# Configure and Run
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/bin/gunicorn", "--paste", "/app/production.ini", "--timeout", "200"]
