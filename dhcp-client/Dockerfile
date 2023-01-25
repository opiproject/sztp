# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM docker.io/library/fedora:37
RUN dnf install -y dhclient && dnf clean all
COPY ./dhclient.conf /etc/dhcp/
CMD ["dhclient", "-d", "-v"]
