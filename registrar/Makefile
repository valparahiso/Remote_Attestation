define registrar =
#!/bin/bash
c++ -O3 -Wall -shared -std=c++11 -fPIC -Iextern/pybind11/include $(python3-config --includes) registrar.cpp pp_api.cpp pp_api.hpp -o registrar$(python3-config --extension-suffix) -lsqlite3 -lssl -lcrypto -lcurl
endef

registrar: ; $(value registrar)

.ONESHELL:

