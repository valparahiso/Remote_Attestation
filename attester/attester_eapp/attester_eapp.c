#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"
#include "calculator.h"
#include <sodium.h>
#include "hacks.h"
#include "channel.h"

#define NONCE_SIZE 64
unsigned char nonce_no_reply[NONCE_SIZE];

void read_nonce()
{
  // struct edge_data nonce;
  // calc_message_t *calc_nonce;
  // size_t nonce_len;

  // ocall_print_buffer("\nAsking untrusted enclave host to receive the nonce from the verifier. . .\n");
  /*ocall_wait_for_message(&nonce);
  calc_nonce = malloc(nonce.size);
  copy_from_shared(calc_nonce, nonce.offset, nonce.size);

  ocall_print_buffer("\nTrying to decrypt the received nonce. . .\n");
  if (channel_recv((unsigned char *)calc_nonce, nonce.size, &nonce_len) != 0)
  {
    free(calc_nonce);
    ocall_print_buffer("Decryption failed, shutting down attester...");
    EAPP_RETURN(1);
  }*/

  ocall_wait_for_nonce(nonce_no_reply, NONCE_SIZE);

  /*for (int i = 0; i < NONCE_SIZE; i++)
  {
    nonce_no_reply[i] = calc_nonce->msg[i];
  }*/

  ocall_print_buffer("NONCE RECEIVED:\n");
  ocall_print_buffer((char *)nonce_no_reply);
}

void generate_and_send_attestation_report()
{
  unsigned char *report_buffer;
  size_t report_size = ocall_get_report_size();
  unsigned char data_section[NONCE_SIZE];

  for (int i = 0; i < NONCE_SIZE; i++)
    data_section[i] = nonce_no_reply[i];

  report_buffer = malloc(report_size);

  ocall_print_buffer("\nTrying to generate attestation report. . .\n");
  attest_enclave((void *)report_buffer, data_section, NONCE_SIZE); // dev_key è dentro bootrom

  ocall_print_buffer("Attestation report correctly generated\n");

  /*ocall_print_buffer("\nTrying to encrypt attestation report. . .\n");
  size_t report_size_encrypted = channel_get_send_size(report_size);
  unsigned char *report_buffer_encrypted = malloc(report_size_encrypted);

  if (report_buffer_encrypted == NULL)
  {
    ocall_print_buffer("Report too large to allocate, no report sent\n");
    ocall_print_buffer("Shutting down attester...");
    EAPP_RETURN(1);
  }

  channel_send((unsigned char *)report_buffer, report_size, report_buffer_encrypted);*/

  ocall_print_buffer("\nAsking untrusted enclave host to send to verifier attestation report. . .\n");
  ocall_send_report((char *)report_buffer, report_size);
  free(report_buffer);
  // free(report_buffer_encrypted);
}

void receive_and_send_public_key()
{
  ocall_print_buffer("\nAsking untrusted enclave host to receive the verifier public key to generate session keys\n");
  ocall_wait_for_client_pubkey(client_pk, crypto_kx_PUBLICKEYBYTES);

  ocall_print_buffer("\nAsking untrusted enclave host to send the attester public key to generate session keys\n");
  ocall_send_server_pubkey(attester_pk, crypto_kx_PUBLICKEYBYTES);
}

void handle_messages()
{

  struct edge_data msg;
  while (1)
  {
    ocall_wait_for_message(&msg);
    calc_message_t *calc_msg = malloc(msg.size);
    size_t wordmsg_len;

    if (calc_msg == NULL)
    {
      ocall_print_buffer("Message too large to store, ignoring\n");
      continue;
    }

    copy_from_shared(calc_msg, msg.offset, msg.size);
    if (channel_recv((unsigned char *)calc_msg, msg.size, &wordmsg_len) != 0)
    {
      free(calc_msg);
      continue;
    }

    if (calc_msg->msg_type == CALC_MSG_EXIT)
    {
      ocall_print_buffer("Received exit, exiting\n");
      EAPP_RETURN(0);
    }

    int val = word_count(calc_msg->msg, wordmsg_len);

    // Done with the message, free it
    free(calc_msg);

    size_t reply_size = channel_get_send_size(sizeof(int));
    unsigned char *reply_buffer = malloc(reply_size);
    if (reply_buffer == NULL)
    {
      ocall_print_buffer("Reply too large to allocate, no reply sent\n");
      continue;
    }

    channel_send((unsigned char *)&val, sizeof(int), reply_buffer);
    ocall_send_reply(reply_buffer, reply_size);

    free(reply_buffer);
  }
}

void EAPP_ENTRY eapp_entry()
{
  edge_init();

  ocall_print_buffer("Enclave correctly started\n");

  // magic_random_init(); // initializing randomndess

  // channel_init(); // generate keypair

  // receive_and_send_public_key(); // need to send pub key generated by channel init to encrypt the communication between eapp and verifier

  // channel_establish(); // once we have exchanged keys we can establish encrypted channel

  read_nonce(); // get the nonce from the verifier

  generate_and_send_attestation_report(); // generate and send the quote

  // handle_messages(); 

  while (1)
  {
    
  }

  EAPP_RETURN(0);
}
