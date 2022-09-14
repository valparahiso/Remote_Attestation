define registrar =
#!/bin/bash
c++ -O3 -Wall -shared -std=c++11 -fPIC -Iextern/pybind11/include $(python3-config --includes) registrar.cpp -o registrar$(python3-config --extension-suffix)
endef

registrar: ; $(value registrar)

.ONESHELL:

