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

char *read_nonce()
{
  struct edge_data nonce;
  calc_message_t *calc_nonce;
  size_t nonce_len;

  ocall_wait_for_message(&nonce);
  calc_nonce = malloc(nonce.size);
  copy_from_shared(calc_nonce, nonce.offset, nonce.size);
  if (channel_recv((unsigned char *)calc_nonce, nonce.size, &nonce_len) != 0)
  {
    free(calc_nonce);
    ocall_print_buffer("Shutting down server...");
    EAPP_RETURN(1);
  }

  ocall_print_buffer("NONCE RICEVUTO:\n");
  ocall_print_buffer(calc_nonce->msg);

  return calc_nonce->msg;
}

void attest_and_establish_channel()
{
  // TODO sizeof report
  char buffer[2048];
  char data_section[NONCE_SIZE + crypto_kx_PUBLICKEYBYTES];
  char *nonce;

  ocall_wait_for_client_pubkey(client_pk, crypto_kx_PUBLICKEYBYTES);
  nonce = read_nonce();

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; i++)
    data_section[i] = server_pk[i];

  for (int i = 0; i < NONCE_SIZE; i++)
    data_section[i + crypto_kx_PUBLICKEYBYTES] = nonce[i];

  attest_enclave((void *)buffer, data_section, crypto_kx_PUBLICKEYBYTES + NONCE_SIZE);
  ocall_send_report(buffer, 2048);

  channel_establish();
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
  magic_random_init();
  channel_init();

  attest_and_establish_channel();
  handle_messages();

  EAPP_RETURN(0);
}
