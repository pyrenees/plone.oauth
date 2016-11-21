FROM python:3.5-slim
MAINTAINER Ramon Navarro Bosch

# Update packages
RUN apt-get update -y

# Install Python Setuptools
RUN apt-get install -y libldap-dev libsasl2-dev locales git-core gcc netcat build-essential

RUN mkdir /app

# Bundle app source
ADD . /app

ENV LANG C.UTF-8
ENV LANGUAGE C.UTF-8
ENV LC_ALL C.UTF-8

# Clean buildout
RUN cd /app; rm -rf .installed.cfg .mr.developer.cfg parts/ eggs/ develop-eggs/
RUN cd /app; find . -name '*.pyc' -or -name '*.egg-info' | xargs rm -rf

# Install buildout
RUN cd /app; python3.5 bootstrap.py

# Run buildout
RUN cd /app; ./bin/buildout -n -vvv

# Expose
EXPOSE  6543

# Configure and Run
ENTRYPOINT ["/app/docker-entrypoint.sh"]
