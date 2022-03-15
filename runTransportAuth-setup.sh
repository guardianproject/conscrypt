#!/bin/sh -ex
#
# To set up the MITM test:
#   git clone https://github.com/guardianproject/masque-mitm.git
#   cd masque-mitm/proxy-router
#   vagrant up
#   curl https://raw.githubusercontent.com/guardianproject/conscrypt/MASQUE/runTransportAuth-setup.sh | vagrant ssh
#   cd masque-mitm/proxied-vm
#   vagrant up
#   curl https://raw.githubusercontent.com/guardianproject/conscrypt/MASQUE/runTransportAuth-setup.sh | vagrant ssh

echo "deb https://security.debian.org/debian-security stretch/updates main" | sudo tee /etc/apt/sources.list.d/stretch-security.list

sudo apt-get update
sudo apt-get -qy install ca-certificates git openjdk-8-jdk-headless

git clone --depth 1 --branch MASQUE https://github.com/guardianproject/conscrypt.git
