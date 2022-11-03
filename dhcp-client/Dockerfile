FROM docker.io/library/fedora:38
RUN dnf install -y dhclient && dnf clean all
COPY ./dhclient.conf /etc/dhcp/
CMD ["dhclient", "-d", "-v"]
