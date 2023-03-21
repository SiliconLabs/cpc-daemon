#!/bin/bash

rm -rf build
mkdir build
cd build
cmake ../ -DENABLE_ENCRYPTION=FALSE
make

sudo make install
sudo ldconfig
