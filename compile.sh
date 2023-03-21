#!/bin/bash

apt-get update -y && apt-get install -y --no-install-recommends make cmake sudo g++
rm -rf build
mkdir build
cd build
cmake ../ -DENABLE_ENCRYPTION=FALSE
make

sudo make install
sudo ldconfig
