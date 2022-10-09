#include <string.h>
#include "trusted_verifier.hpp"
#include "verifier_db_op.hpp"

#include <sqlite3.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#define NONCE_SIZE 64

unsigned char verifier_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char verifier_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];
unsigned char nonce[NONCE_SIZE];

int double_fault;
int channel_ready;
bool attestor_valid = false;
bool report_valid = false;
bool libsodium_init = false;

int calcDecodeLength(const char *b64input)
{ // Calculates the length of a decoded base64 string
  int len = strlen(b64input);
  int padding = 0;

  if (b64input[len - 1] == '=' && b64input[len - 2] == '=') // last two chars are =
    padding = 2;
  else if (b64input[len - 1] == '=') // last char is =
    padding = 1;

  return (int)len * 0.75 - padding;
}

int Base64Decode(char *b64message, char **buffer)
{ // Decodes a base64 encoded string
  BIO *bio, *b64;
  int decodeLen = calcDecodeLength(b64message),
      len = 0;
  *buffer = (char *)malloc(decodeLen + 1);
  FILE *stream = fmemopen(b64message, strlen(b64message), "r");

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
  len = BIO_read(bio, *buffer, strlen(b64message));
  // Can test here if len == decodeLen - if not, then return an error
  (*buffer)[len] = '\0';

  BIO_free_all(bio);
  fclose(stream);

  return (0); // success
}

static int check_attestor_callback(void *report, int count, char **data, char **columns)
{
  if (count == 0)
  {
    return 0;
  }

  char *res;
  Report *received_report = reinterpret_cast<Report *>(report);
  Base64Decode(data[0], &res);

  if (received_report->checkSignaturesOnly((unsigned char *)res))
  {
    attestor_valid = true;
  }

  return 0;
}

void check_attestor(Report report, int attester_id)
{
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;
  attestor_valid = false;
  char sql[256];

  /* Open database */
  rc = sqlite3_open("../db/gvalues.db", &db);

  if (rc)
  {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  /* Create SQL statement */
  sprintf(sql, "SELECT pubkey, id from attestors WHERE id=%d", attester_id);

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, check_attestor_callback, &report, &zErrMsg);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }

  sqlite3_close(db);
  return;
}

static int select_gvalues_callback(void *report, int count, char **data, char **columns)
{
  unsigned char *sm_hash;
  unsigned char *enclave_hash;
  unsigned char *pubkey;

  Report *received_report = reinterpret_cast<Report *>(report);

  for (int idx = 0; idx < count; idx++)
  {
    char *res;
    Base64Decode(data[idx], &res);
    if (!strcmp(columns[idx], "sm_hash"))
    {
      sm_hash = (unsigned char *)res;
    }
    else if (!strcmp(columns[idx], "enclave_hash"))
    {
      enclave_hash = (unsigned char *)res;
    }
    else if (!strcmp(columns[idx], "pubkey"))
    {
      pubkey = (unsigned char *)res;
    }
  }

  report_valid |= received_report->verify(enclave_hash, sm_hash, pubkey);

  return 0;
}

void select_gvalues(Report report, int attester_id, int eapp_id)
{
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;
  char sql[256];

  /* Open database */
  rc = sqlite3_open("../db/gvalues.db", &db);

  if (rc)
  {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  /* Create SQL statement */
  sprintf(sql, "SELECT COUNT(*), G.enclave_hash, G.sm_hash, A.pubkey FROM gvalues AS G, attestors AS A WHERE G.attestor=A.id AND G.attestor=%d AND G.eapp=%d", attester_id, eapp_id);

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, select_gvalues_callback, &report, &zErrMsg);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }

  sqlite3_close(db);
  return;
}

void update_status_and_timestamp(bool attester, char *status, int id)
{
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;
  char sql[256];

  time_t timer;
  char timestamp[26];
  struct tm *tm_info;

  timer = time(NULL);
  tm_info = localtime(&timer);

  strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

  /* Open database */
  rc = sqlite3_open("../db/gvalues.db", &db);

  if (rc)
  {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return;
  }

  /* Create SQL statement */
  sprintf(sql, "UPDATE %s SET status = \"%s\", timestamp = \"%s\" WHERE id=%d", (attester ? "attestors" : "eapps"), status, timestamp, id);

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  }

  sqlite3_close(db);
  return;
}

void trusted_verifier_exit()
{
  if (double_fault || !channel_ready)
  {
    printf("DC: Fatal error, exiting. Remote not cleanly shut down.\n");
    exit(-1);
  }
  else
  {
    double_fault = 1;
    printf(" Exiting. Attempting clean remote shutdown.\n");
    //send_exit_message();
    exit(0);
  }
}

/*void trusted_verifier_init()
{
  int ret = 0;
  if (!libsodium_init)
    ret = sodium_init();

  if (ret != 0)
  {
    printf("Libsodium initialization failure\n");
    trusted_verifier_exit();
  }

  libsodium_init = true;
  if (crypto_kx_keypair(verifier_pk, verifier_sk) != 0)
  {
    printf("Libsodium keypair generation failure\n");
    trusted_verifier_exit();
  }

  channel_ready = 0;
}*/

byte *trusted_verifier_pubkey(size_t *len)
{
  *len = crypto_kx_PUBLICKEYBYTES;
  return (byte *)verifier_pk;
}

bool verify_data_section(Report report)
{
  char *data_section;
  if (report.getDataSize() != NONCE_SIZE)
  {
    printf("Bad report data section size\n");
    return false;
  }

  data_section = (char *)report.getDataSection();

  for (int i = 0; i < NONCE_SIZE; i++)
  {
    if ((char)nonce[i] != data_section[i])
    {
      printf("Returned data in the report do NOT match with the nonce sent\n");
      return false;
    }
  }
  printf("Returned data in the report match with the nonce sent.\n");

  return true;
}

bool trusted_verifier_attest_report(unsigned char *buffer, size_t report_size, int attester_id, int eapp_id)
{
  printf("\nTrying to decrypt with session keys the received report. . .\n");
  /*if (!trusted_verifier_unbox(buffer, report_size))
    return false;*/

  Report report;
  report.fromBytes(buffer);

  printf("\n**********     Received Report:     **********\n");
  report.printPretty();

  printf("\nStarting to attest the received report. . .\n");
  check_attestor(report, attester_id);

  if (!attestor_valid)
  {
    printf("Server public key is not in the whitelist\n");

    update_status_and_timestamp(false, "INVALID", eapp_id);
    return true;
  }

  printf("Server public key is in the whitelist, proceeding validating report\n");
  attestor_valid = false;

  select_gvalues(report, attester_id, eapp_id);

  if (report_valid && verify_data_section(report))
  {
    printf("Attestation signature and enclave hash are valid\n");
    update_status_and_timestamp(false, "VALID", eapp_id);
    report_valid = false;
  }
  else
  {
    printf("Attestation report is NOT valid\n");
    update_status_and_timestamp(false, "INVALID", eapp_id);
  }

  return true;
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len + (MSG_BLOCKSIZE - (len % MSG_BLOCKSIZE)))

/*byte *trusted_verifier_box(byte *msg, size_t size, size_t *finalsize)
{
  size_t size_padded = BLOCK_UP(size);
  *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
  byte *buffer = (byte *)malloc(*finalsize);
  if (buffer == NULL)
  {
    printf("No memory for message\n");
    trusted_verifier_exit();
  }

  memcpy(buffer, msg, size);

  size_t buf_padded_len;
  if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0)
  {
    printf("Unable to pad message, exiting\n");
    trusted_verifier_exit();
  }

  unsigned char *nonceptr = &(buffer[crypto_secretbox_MACBYTES + buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

  if (crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0)
  {
    printf("Crypto secretbox failed\n");
    trusted_verifier_exit();
  }

  printf("Message correctly encrypted\n");
  return (buffer);
}*/

/*bool trusted_verifier_unbox(unsigned char *buffer, size_t len)
{
  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char *nonceptr = &(buffer[clen]);

  if (crypto_secretbox_open_easy(buffer, buffer, clen, nonceptr, rx) != 0)
  {
    printf("Crypto unbox failed\n");
    return false;
  }

  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
  size_t unpad_len;
  if (sodium_unpad(&unpad_len, buffer, ptlen, MSG_BLOCKSIZE) != 0)
  {
    printf("Invalid message padding, ignoring\n");
    return false;
  }

  printf("Message correctly decrypted\n");

  return true;
}*/

bool exchange_keys_and_establish_channel()
{
  printf("\nTrying to send generated verifier public key to the attester. . .\n");
  send_buffer(verifier_pk, crypto_kx_PUBLICKEYBYTES);

  size_t public_key_size;
  printf("\nTrying to receive generated attester public key from the attester. . .\n");
  byte *attester_key = recv_buffer(&public_key_size);

  if (!strcmp((char *)attester_key, "ERROR"))
    return false;

  if (public_key_size != crypto_kx_PUBLICKEYBYTES)
  {
    printf("Wrong size received for the attester public key\n");
    return false;
  }

  for (int i = 0; i < crypto_kx_PUBLICKEYBYTES; i++)
  {
    server_pk[i] = attester_key[i];
  }

  printf("\nTrying to generate session keys to establish an encrypted channel between eapp and verifier. . .\n");
  //channel_establish(); // generating encrypted channel from eapp to verifier
  return true;
}

/*void channel_establish()
{
  if (crypto_kx_client_session_keys(rx, tx, verifier_pk, verifier_sk, server_pk) != 0)
  {
    printf("Bad session key generation\n");
    trusted_verifier_exit();
  }

  printf("Session keys generated\n");
  channel_ready = 1;
}*/

int trusted_verifier_read_reply(unsigned char *data, size_t len)
{

  //trusted_verifier_unbox(data, len);

  int *replyval = (int *)data;

  printf(" Enclave said string was %i words long\n", *replyval);

  return *replyval;
}

/*void send_exit_message()
{

  size_t pt_size;
  calc_message_t *pt_msg = generate_exit_message(&pt_size);

  size_t ct_size;
  byte *ct_msg = trusted_verifier_box((byte *)pt_msg, pt_size, &ct_size);

  send_buffer(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);
}*/

/*void send_wc_message(char *buffer)
{

  size_t pt_size;
  calc_message_t *pt_msg = generate_wc_message(buffer, strlen(buffer) + 1, &pt_size);

  size_t ct_size;
  byte *ct_msg = trusted_verifier_box((byte *)pt_msg, pt_size, &ct_size);

  send_buffer(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);
}*/

/*calc_message_t *generate_wc_message(char *buffer, size_t buffer_len, size_t *finalsize)
{
  calc_message_t *message_buffer = (calc_message_t *)malloc(buffer_len + sizeof(calc_message_t));

  message_buffer->msg_type = CALC_MSG_WORDCOUNT;
  message_buffer->len = buffer_len;
  memcpy(message_buffer->msg, buffer, buffer_len);

  *finalsize = buffer_len + sizeof(calc_message_t);

  return message_buffer;
}*/

/*calc_message_t *generate_exit_message(size_t *finalsize)
{

  calc_message_t *message_buffer = (calc_message_t *)malloc(sizeof(calc_message_t));
  message_buffer->msg_type = CALC_MSG_EXIT;
  message_buffer->len = 0;

  *finalsize = sizeof(calc_message_t);

  return message_buffer;
}*/

void send_nonce()
{
  size_t pt_size;
  byte nonce_buffer[NONCE_SIZE];
  memset(nonce_buffer, 0, NONCE_SIZE);

  //randombytes_buf(nonce_buffer, NONCE_SIZE);

  printf("\n**********     Generated random nonce to avoid reply attacks:     **********\n");
  for (int i = 0; i < NONCE_SIZE; i++)
  {
    printf("%02x", (unsigned char)nonce_buffer[i]);
  }
  printf("\n\n");

  memcpy(nonce, nonce_buffer, NONCE_SIZE);
  // calc_message_t *pt_msg = generate_wc_message((char *)nonce_buffer, NONCE_SIZE + 2, &pt_size);

  size_t ct_size;

  printf("\nTrying to encrypt with session keys the generated nonce. . .\n");
  // byte *ct_msg = trusted_verifier_box((byte *)pt_msg, pt_size, &ct_size);

  printf("\nTrying to send the encrypted nonce. . .\n");
  // send_buffer(ct_msg, ct_size);

  // free(pt_msg);
  // free(ct_msg);
}