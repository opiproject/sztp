# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM docker.io/library/fedora:38
RUN dnf install -y dhcp-server gettext && dnf clean all
COPY ./dhcpd.conf.template /etc/dhcp/
CMD ["dhcpd", "-d"]
