# Remote Attestation project using Keystone Framework

This project includes a small enclave server that is capable of remote
attestation and secure channel creation (using [libsodium](https://github.com/jedisct1/libsodium)).


Inside the client and server folders, the "start_client.sh" and 
"start_server.sh" files will clone/build all necessary components for the
project to run in qemu if you have already built [keystone](https://github.com/keystone-enclave/keystone) 
and it's sdk tests successfully.

# Quick Start

The client requires the expected hash of the security monitor.
The hash will be used by the trusted client to verify that the server enclave
is created and initialized by the known version of the SM.

If you want to skip this verification, you can pass in `--ignore-valid` flag
to the client. 

Please see the [security monitor](https://github.com/keystone-enclave/sm)'s documentation to see how to generate a hash.

In order to configure correctly the paths of libsodium try, in both client and server folders:

```
source source.sh
```

Then, once you generated the `sm_expected_hash.h`, try: 

```
SM_HASH=<path/to/sm_expected_hash.h> ./start_client.sh
```
into the client folder, and:

```
./start_server.sh
```

into the server folder.

You should be able to see the server enclave package `demo-server.ke` and the
trusted client `trusted_client.riscv` under `build` directory into the respective folders.

Copy these files into the machine, and run the server enclave.
Then, connect to the server using the client.

```
# on the server side
./demo-server.ke
```

```
# on the client side
./trusted_client.riscv server_address
```

The client will connect to the enclave and perform the remote attestation.
If the attestation is successful, the client can send an arbitrary message to the server
so that the server counts the number of words in the message and reply.

## Attestation Failures

It is expected that the client will reject the attestation report from
the host if you haven't regenerated the expected hashes for the SM and
eapp. Pass the `--ignore-valid` flag to the client for testing.
