FROM docker.io/library/python:3.10.8-slim

RUN apt-get update && apt-get install -y --no-install-recommends libyang-tools libxml2-utils make curl && rm -rf /var/lib/apt/lists/*

# certificates
SHELL ["/bin/bash", "-eo", "pipefail", "-c"]
RUN curl -kL https://watsen.net/support/sztpd-simulator-0.0.11.tgz | tar -zxvf - -C /tmp/
WORKDIR /tmp/sztpd-simulator/pki
RUN sed -i "s/localhost/bootstrap/g" sztpd1/sbi/end-entity/openssl.cnf && \
    make pki && \
    echo # create trust chain && \
    cat sztpd1/sbi/root-ca/my_cert.pem sztpd1/sbi/intermediate1/my_cert.pem > /opi.pem

CMD ["/bin/sh", "-c", "sleep infinity"]
