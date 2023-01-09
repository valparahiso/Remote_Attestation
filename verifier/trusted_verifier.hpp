#ifndef _TRUSTED_VERIFIER_HPP_
#define _TRUSTED_VERIFIER_HPP_

#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sodium.h>
#include "report.h"

typedef unsigned char byte;

void trusted_verifier_exit();
void trusted_verifier_init();
byte *trusted_verifier_pubkey(size_t *len);
bool trusted_verifier_attest_report(unsigned char *buffer, size_t report_size, int attester_id, int eapp_id);
int trusted_verifier_read_reply(unsigned char *data, size_t len);
void send_exit_message();
void send_wc_message(char *buffer);
bool send_nonce();
bool exchange_keys_and_establish_channel();
void channel_establish();
char *generate_nonce();
//calc_message_t *generate_wc_message(char *buffer, size_t buffer_len, size_t *finalsize);
bool update_status_and_timestamp(bool attester, char *status, int id);
//calc_message_t *generate_exit_message(size_t *finalsize);

byte *trusted_verifier_box(byte *msg, size_t size, size_t *finalsize);
bool trusted_verifier_unbox(unsigned char *buffer, size_t len);

#endif /* _TRUSTED_VERIFIER_HPP_ */
