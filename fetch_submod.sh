#!/bin/bash

git submodule init
git submodule update
cd src/runc/
git reset --hard 8fc5be4e60246eb9f7c50e9150f9b1d21f835f8a

