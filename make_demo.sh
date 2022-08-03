#!/bin/bash


echo "1. Compilo il verifier"
mkdir -p verifier/build
cd verifier/trusted_verifier
make

echo "2. Compilo l'attester"
cd ../../attester
./start_server.sh

echo "3. Copio il file generato in qemu"
cp build/demo-attester.ke ../../keystone_edit/build/overlay/root

echo "4. Compilo il nuovo file in qemu"
cd ../../keystone_edit/build 
make image


