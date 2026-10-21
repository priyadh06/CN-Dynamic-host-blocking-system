#!/usr/bin/env bash
# Run once on Ubuntu 24.04 (a VM is fine). Expects this folder at ~/dhbs
set -e
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y mininet openvswitch-switch python3-pip python3-venv git netcat-openbsd tcpdump net-tools iperf3
sudo systemctl enable --now openvswitch-switch
python3 -m venv ~/dhbs/venv
~/dhbs/venv/bin/pip install --upgrade pip
~/dhbs/venv/bin/pip install os-ken==4.2.2
echo "Setup finished. Next: see ~/dhbs/HANDOFF.md"
