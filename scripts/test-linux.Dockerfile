# The image the Linux test runs use. Everything that needs the network is
# installed here, once, so that the test runs themselves can be offline: a test
# that fails because a package index was unreachable is worse than no test.
#
# Python is not incidental. Several tests drive a real client against the server
# rather than a mock -- certificate loading, the HTTP and SOCKS5 inbounds, HTTP
# authentication, DNS-over-HTTPS -- and the client is a Python script.
FROM golang:1.26-alpine

RUN apk add --no-cache python3 py3-pip iproute2 \
 && python3 -m venv /venv \
 && /venv/bin/pip install --no-cache-dir requests flask pysocks cryptography \
 && ln -sf /venv/bin/python /usr/local/bin/python \
 && ln -sf /venv/bin/python3 /usr/local/bin/python3

ENV PATH=/venv/bin:$PATH
