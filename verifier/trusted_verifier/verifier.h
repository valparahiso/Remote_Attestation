#ifndef _VERIFIER_H_
#define _VERIFIER_H_
#include "trusted_verifier.h"

void send_buffer(byte* buffer, size_t len);
byte* recv_buffer(size_t* len);
void init_wolfSSL(); 
void connect_to_attester(char *hostname);

#endif /* _VERIFIER_H_ */
