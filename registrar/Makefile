define registrar =
#!/bin/bash
c++ -O3 -Wall -shared -std=c++11 -fPIC -Iextern/pybind11/include $(python3-config --includes) registrar.cpp registrar_db_op.cpp registrar_db_op.hpp -o registrar$(python3-config --extension-suffix) -lsqlite3 -lssl -lcrypto
endef

registrar: ; $(value registrar)

.ONESHELL:

