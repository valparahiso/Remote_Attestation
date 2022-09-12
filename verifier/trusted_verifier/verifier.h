#ifndef _VERIFIER_H_
#define _VERIFIER_H_
#include "trusted_verifier.h"

void send_buffer(byte* buffer, size_t len);
byte* recv_buffer(size_t* len);
void connect_to_attester(char *hostname, uint16_t port);
void str_to_uint16(const char *str, uint16_t *res);
void close_wolfSSL();
void get_attesters();
void get_eapps(int id, int i);

#endif /* _VERIFIER_H_ */
