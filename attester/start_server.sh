#!/bin/bash

set -e

echo -e "This is a attester START build script for the Remote Attestation project, 
it will clone and build all the necessary parts to run the attester/applcation
on a RISC-V platform (ex: qemu). Please ensure you have cloned keystone completely 
and that you have fully built the sdk tests and run them successfully in qemu.

You must set KEYSTONE_SDK_DIR to the install directory of Keystone SDK.

You must have the riscv64 gcc on-path as well. (e.g. run
'source source.sh' in the Keystone directory.

If you have already started building libsodium/etc, it is not
recommended to use this script."
read -r -p "Continue? [Y/n] " response 
response=${response,,}
if [[ "$response" =~ ^(no|n)$ ]]
then
    exit 0
fi

# Check location/tools
if [[ ! -v KEYSTONE_SDK_DIR ]]
then
    echo "KEYSTONE_SDK_DIR not set! Please set this to the location where Keystone SDK has been installed."
    exit 0
fi

if [[ ! $(command -v riscv64-unknown-linux-gnu-gcc) ]]
then
    echo "No riscv64 gcc available. Make sure you've run \"source source.sh\" in the Keystone directory (or equivalent.)";
    exit 0
fi

DEMO_DIR=$(pwd)

set -e

mkdir -p libsodium_builds
cd libsodium_builds

# Clone, checkout, and build the attester libsodium
if [ ! -d libsodium_attester ]
then
  git clone https://github.com/jedisct1/libsodium.git libsodium_attester
  cd libsodium_attester
  git checkout 4917510626c55c1f199ef7383ae164cf96044aea
  patch -p1 < $DEMO_DIR/sodium_patches/configure.ac.patch
  ./autogen.sh
  ./configure --host=riscv64-unknown-linux-gnu --disable-ssp --disable-asm --without-pthreads
  make
  cd ..
fi
export LIBSODIUM_DIR=$(pwd)/libsodium_attester/src/libsodium/

cd ..

# Build the demo
mkdir -p build
cd build
cmake ..
make
make package

# Done!
echo -e "************ Demo binaries built and copied into overlay directory. ***************
            Run 'make image' in the Keystone build dir, and the demo binaries should
            be available in qemu next time you start it!"
