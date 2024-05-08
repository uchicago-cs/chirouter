# Based on https://github.com/iwaseyusuke/docker-mininet/tree/main

FROM ubuntu:22.04

USER root
WORKDIR /chirouter
ENV DEBIAN_FRONTEND=noninteractive

COPY docker/ENTRYPOINT.sh docker/run-tests docker/run-grade run-mininet run-controller /chirouter/
COPY scripts/webserver.py /chirouter/scripts/
COPY topologies/ /chirouter/topologies/
COPY src/python/chirouter/*.py /chirouter/src/python/chirouter/
COPY src/python/chirouter/tests/ /chirouter/src/python/chirouter/tests/

# Install tools and dependencies
RUN <<EOF
apt update && apt install -y --no-install-recommends \
  wget dnsutils iputils-ping traceroute net-tools \
  sudo nano less curl patch python3-pip git \
  libssl-dev libxml2-dev libxslt1-dev
pip3 install click pytest pytest-json
EOF

# Install mininet
RUN <<EOF
cd /tmp
git clone https://github.com/mininet/mininet
cd mininet
git checkout -b mininet-2.3.1b4 2.3.1b4
cd ..
PYTHON=python3 mininet/util/install.sh -nfv
EOF

# Install Ryu
# We're installing a fork of the official Ryu repository because
# the official repository won't work on Ubuntu 22.04
# (https://github.com/faucetsdn/ryu/issues/169). In the
# long term, we should switch to a different controller, since
# Ryu is no longer actively maintained.
RUN <<EOF
cd /opt
git clone https://github.com/paaguti/ryu.git
cd ryu
pip3 install .
pip3 install dnspython==2.2.1
EOF

# Cleanup
RUN <<EOF
apt remove -y --purge "*-dev" "libgl1*" libllvm15
apt autoremove
rm -rf /var/lib/apt/lists/*
touch /etc/network/interfaces
chmod +x /chirouter/ENTRYPOINT.sh /chirouter/run-tests /chirouter/run-grade
EOF

ENTRYPOINT ["/chirouter/ENTRYPOINT.sh"]
