#ifndef _TRUSTED_VERIFIER_H_
#define _TRUSTED_VERIFIER_H_

#include <stdio.h>
#include "calc_msg.h"

#include <string>
#include <iostream>
#include <fstream>
#include "trusted_verifier.h"
#include <sodium.h>
#include "report.h"


typedef unsigned char byte;

void trusted_verifier_exit();
void trusted_verifier_init();
byte* trusted_verifier_pubkey(size_t* len);
void trusted_verifier_get_report(void* buffer);
int trusted_verifier_read_reply(unsigned char* data, size_t len);
void send_exit_message();
void send_wc_message(char* buffer);
void send_nonce();
void exchange_keys_and_establish_channel();
void channel_establish();
char* generate_nonce();
calc_message_t* generate_wc_message(char* buffer, size_t buffer_len, size_t* finalsize);
calc_message_t* generate_exit_message(size_t* finalsize);


byte* trusted_verifier_box(byte* msg, size_t size, size_t* finalsize);
void trusted_verifier_unbox(unsigned char* buffer, size_t len);

#endif /* _TRUSTED_VERIFIER_H_ */
