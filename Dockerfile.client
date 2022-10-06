FROM docker.io/library/fedora:36
RUN dnf install -y dhclient && dnf clean all
COPY ./dhclient.conf /etc/dhcp/
CMD ["dhclient", "-d", "-v"]
