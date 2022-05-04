# Remote Attestation project using Keystone Framework

This project includes a small enclave server that is capable of remote
attestation and secure channel creation (using [libsodium](https://github.com/jedisct1/libsodium)).


Inside the client and server folders, the "start_client.sh" and 
"start_server.sh" files will clone/build all necessary components for the
project to run in qemu if you have already built [keystone](https://github.com/keystone-enclave/keystone) 
and it's sdk tests successfully.

# Quick Start

In order to configure correctly the paths of libsodium try, in and server folder:

```
source source.sh
```

and 

```
sudo apt-get install -y libsodium-dev
```

in client folder.

Then try: 

```
./start_server.sh
```

into the server folder
and 

```
cd trusted_client
make
```
into the client folder.

You should be able to see the server enclave package `demo-server.ke` and the
trusted client `trusted_client.8086` under `build` directory into the respective folders.

Copy these files into the machine, and run the server enclave.
Then, connect to the server using the client.

```
# on the server side
./demo-server.ke
```

```
# on the client side
./trusted_client.8086 server_address
```

The client will connect to the enclave and perform the remote attestation.
If the attestation is successful, the client can send an arbitrary message to the server
so that the server counts the number of words in the message and reply.

