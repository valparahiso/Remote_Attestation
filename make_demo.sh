#!/bin/bash


read -p "1. Compilo il verifier . . . Press any key to continue . . . " -n1 -s 
cd verifier
make

read -p "2. Compilo l'attester . . . Press any key to continue . . . " -n1 -s
cd ../attester
./start_server.sh

read -p "3. Copio il file generato in qemu . . . Press any key to continue . . " -n1 -s
cp build/demo-attester.ke ../../keystone_edit/build/overlay/root

echo ". "

read -p "4. Compilo il nuovo file in qemu . . . Press any key to continue . . . " -n1 -s
rm -r ../../keystone_edit/build/buildroot.build/target/root/*
cd ../../keystone_edit/build 
make image


