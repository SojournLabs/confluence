FROM debian
MAINTAINER jonathan lung <vapr@sojournlabs.com>
RUN apt-get update
RUN apt-get install -y \
    wget
WORKDIR /installers/confluence
ADD response.varfile response.varfile
RUN useradd --create-home -c "Atlassian Confluence" confluence
VOLUMES ["/var/confluence"]
WORKDIR /var/confluence
