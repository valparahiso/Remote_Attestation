trusted-verifier: verifier.cpp verifier.h trusted_verifier.cpp trusted_verifier.h
	g++ -L${KEYSTONE_SDK_DIR} -L/usr/lib/x86_64-linux-gnu -Wall -o ../build/verifier.x86 verifier.cpp verifier.h trusted_verifier.cpp trusted_verifier.h -I/usr/include/sodium -I../include -I${KEYSTONE_SDK_DIR}/include -I${KEYSTONE_SDK_DIR}/include/verifier -lkeystone -lsodium -lsqlite3 -lssl -lcrypto 
  
