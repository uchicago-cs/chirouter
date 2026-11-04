FROM ubuntu:24.04

USER root
WORKDIR /chirouter
ENV DEBIAN_FRONTEND=noninteractive

# Ubuntu 24.04 doesn't allow installing Python packages system-wide
# with pip (PEP 668). That's fine inside this container.
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# Install tools and dependencies. The versions of the Python packages are
# pinned so that rebuilding the image doesn't change how the tests behave
# (in particular, the tests depend on how jc parses the output of ping and
# traceroute). Mininet only needs iproute2 and net-tools, and ethtool (to
# disable offloads); Open vSwitch is not needed.
RUN <<EOF
apt-get update && apt-get install -y --no-install-recommends \
  iproute2 net-tools ethtool \
  iputils-ping traceroute wget curl dnsutils \
  sudo nano less psmisc \
  python3 python3-pip python3-pexpect python3-packaging \
  git make gcc libc6-dev
pip3 install click==8.5.0 pytest==9.2.0 pytest-json-report==1.5.0 jc==1.26.2
EOF

# Install Mininet (only the Python package and mnexec; we don't
# use Mininet's install.sh, since we don't need Open vSwitch or
# any OpenFlow controllers)
RUN <<EOF
cd /tmp
git clone --depth 1 --branch 2.3.1b4 https://github.com/mininet/mininet
cd mininet
make PYTHON=python3 mnexec
install mnexec /usr/bin/
pip3 install .
cd /tmp
rm -rf mininet
EOF

# Cleanup
RUN <<EOF
apt-get remove -y --purge git make gcc libc6-dev
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*
EOF

COPY docker/ENTRYPOINT.sh docker/run-tests docker/run-grade run-mininet /chirouter/
COPY scripts/webserver.py /chirouter/scripts/
COPY topologies/ /chirouter/topologies/
COPY src/python/chirouter/*.py /chirouter/src/python/chirouter/
COPY src/python/chirouter/tests/ /chirouter/src/python/chirouter/tests/
RUN chmod +x /chirouter/ENTRYPOINT.sh /chirouter/run-tests /chirouter/run-grade /chirouter/run-mininet

ENTRYPOINT ["/chirouter/ENTRYPOINT.sh"]
