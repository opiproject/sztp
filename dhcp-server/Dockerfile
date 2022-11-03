FROM docker.io/library/fedora:38
RUN dnf install -y dhcp-server gettext && dnf clean all
COPY ./dhcpd.conf.template /etc/dhcp/
CMD ["dhcpd", "-d"]
