#include "eapp_utils.h"
#include "sodium.h"
#include "channel.h"
#include "string.h"
#include "edge_wrapper.h"

unsigned char attester_pk[crypto_kx_PUBLICKEYBYTES], attester_sk[crypto_kx_SECRETKEYBYTES];
unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];

void channel_init(){

  ocall_print_buffer("\n Trying to generate attester keypair using libsodium\n");
  /* libsodium config */
  randombytes_set_implementation(&randombytes_salsa20_implementation);

  if(sodium_init() < 0 ){
    ocall_print_buffer("Sodium initialization failed, exiting\n");
    EAPP_RETURN(1);
  }

  /* Generate our keys */
  if(crypto_kx_keypair(attester_pk, attester_sk) != 0){
    ocall_print_buffer("Unable to generate keypair, exiting\n");
    EAPP_RETURN(1);
  }

  ocall_print_buffer("Attester keypair correctly generated\n");

}

void channel_establish(){

  ocall_print_buffer("\nTrying to generate session keys. . .\n");
  /* Ask libsodium to generate session keys based on the recv'd pk */

  if(crypto_kx_server_session_keys(rx, tx, attester_pk, attester_sk, client_pk) != 0) {
    ocall_print_buffer("Unable to generate session keys, exiting\n");
    EAPP_RETURN(1);
  }
  ocall_print_buffer("Successfully generated session keys\n");
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

int channel_recv(unsigned char* msg_buffer, size_t len, size_t* datalen){
  /* We store the nonce at the end of the ciphertext buffer for easy
     access */
  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(msg_buffer[clen]);

  if (crypto_secretbox_open_easy(msg_buffer, msg_buffer, clen, nonceptr, rx) != 0){
    ocall_print_buffer("Invalid message, ignoring\n");
    return -1;
  }
  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

  size_t unpad_len;
  if( sodium_unpad(&unpad_len, msg_buffer, ptlen, MSG_BLOCKSIZE) != 0){
    ocall_print_buffer("Invalid message padding, ignoring\n");
    return -1;
  }

  *datalen = unpad_len;

  ocall_print_buffer("Message decrypted correctly\n");

  return 0;
}


size_t channel_get_send_size(size_t len){
  return crypto_secretbox_MACBYTES + BLOCK_UP(len) + crypto_secretbox_NONCEBYTES;
}

void channel_send(unsigned char* msg, size_t len, unsigned char* buffer){
  /* We store the nonce at the end of the ciphertext buffer for easy
     access */

  size_t buf_padded_len;

  memcpy(buffer, msg, len);

  if (sodium_pad(&buf_padded_len, buffer, len, MSG_BLOCKSIZE, BLOCK_UP(len)) != 0) {
    ocall_print_buffer("Unable to pad message, exiting\n");
    EAPP_RETURN(1);
  }

  unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

  if(crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0){
    ocall_print_buffer("Unable to encrypt message, exiting\n");
    EAPP_RETURN(1);
  }

  ocall_print_buffer("Message encrypted correctly\n");
}
