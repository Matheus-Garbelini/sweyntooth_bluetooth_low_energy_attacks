#!/usr/bin/env bash
sudo apt install python-dev gcc g++ make -y
python -m pip install -r requirements.txt
cd ./libs/smp_server/
make build
sudo make install
cd ../
