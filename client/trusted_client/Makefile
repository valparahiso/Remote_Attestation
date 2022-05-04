trusted-client: client.cpp client.h trusted_client.cpp trusted_client.h
	g++ -L${KEYSTONE_SDK_DIR} -L/usr/lib/x86_64-linux-gnu -Wall -o ../build/trusted-client.8086 client.cpp client.h trusted_client.cpp trusted_client.h -I/usr/include/sodium -I../include -I${KEYSTONE_SDK_DIR}/include -I${KEYSTONE_SDK_DIR}/include/verifier -lkeystone -lsodium -lsqlite3 -lssl -lcrypto 
