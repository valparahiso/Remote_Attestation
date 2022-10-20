define verifier = 
 #!/bin/bash
c++ -O3 -L${KEYSTONE_SDK_DIR} -L/usr/lib/x86_64-linux-gnu -Wall -shared -std=c++11 -fPIC -I/extern -I${KEYSTONE_SDK_DIR}/include -I${KEYSTONE_SDK_DIR}/include/verifier -I/usr/include/sodium -Iextern/pybind11/include $(python3-config --includes) verifier.cpp attestation.cpp attestation.hpp trusted_verifier.cpp trusted_verifier.hpp registration.cpp registration.hpp -o verifier$(python3-config --extension-suffix) -lsqlite3 -lssl -lcrypto -lwolfssl -lkeystone
endef

verifier: ; $(value verifier)

.ONESHELL:
