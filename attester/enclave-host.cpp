#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include "keystone.h"
#include "edge_wrapper.h"
#include "encl_message.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define PRINT_MESSAGE_BUFFERS 1

/* We hardcode these for demo purposes. */
const char *enc_path = "attester_eapp.eapp_riscv";
const char *runtime_path = "eyrie-rt";

#define PORTNUM 1111
#define CERT_FILE "/root/certs/server-cert.pem"
#define KEY_FILE "/root/certs/server-key.pem"
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];
int fd_clientsock;
/* declare wolfSSL objects */
WOLFSSL_CTX *ctx = NULL;
WOLFSSL *ssl = NULL;

void send_buffer(byte *buffer, size_t len)
{
  /* Reply back to the client */
  if ((wolfSSL_write(ssl, &len, sizeof(size_t))) != sizeof(size_t))
  {
    printf("ERROR: failed to write size of message\n");
    exit(-1);
  }

  printf("Sto inviando un buffer di %li di size\n", len);

  if ((wolfSSL_write(ssl, buffer, len)) != len)
  {
    printf("ERROR: failed to write message for client\n");
    exit(-1);
  }
  // write(fd_clientsock, &len, sizeof(size_t));
  // write(fd_clientsock, buffer, len);
}

byte *recv_buffer(size_t *len)
{
  /* Read the client data into our buff array */
  memset(local_buffer, 0, sizeof(local_buffer));
  if ((wolfSSL_read(ssl, local_buffer, sizeof(size_t))) == 0)
  {
    printf("ERROR: failed to read length\n");
    exit(-1);
  }
  // read(fd_clientsock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t *)local_buffer;
  byte *reply = (byte *)malloc(reply_size);

  if ((wolfSSL_read(ssl, reply, reply_size)) == -1)
  {
    printf("ERROR: failed to read reply\n");
    exit(-1);
  }
  // read(fd_clientsock, reply, reply_size);
  *len = reply_size;
  return reply;
}

void print_hex_data(unsigned char *data, size_t len)
{
  unsigned int i;
  std::string str;
  for (i = 0; i < len; i += 1)
  {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();
    if (i > 0 && (i + 1) % 8 == 0)
    {
      if ((i + 1) % 32 == 0)
      {
        str += "\n";
      }
      else
      {
        str += " ";
      }
    }
  }
  printf("%s\n\n", str.c_str());
}

unsigned long print_buffer(char *str)
{
  printf("[SE] %s", str);

  printf("\n********HEX*********\n");
  for (int i = 0; i < strlen(str); i++)
  {
    printf("%02x", (unsigned char)str[i]);
  }

  printf("\n\n\n");
  return strlen(str);
}

void print_value(unsigned long val)
{
  printf("[SE] value: %u\n", val);
  return;
}

void send_reply(void *data, size_t len)
{
  printf("[EH] Sending encrypted reply:\n");

  if (PRINT_MESSAGE_BUFFERS)
    print_hex_data((unsigned char *)data, len);

  send_buffer((byte *)data, len);
}

void *wait_for_client_pubkey()
{
  size_t len;
  byte *pubkey_client = recv_buffer(&len);

  printf("[EH] Received client public key: %s\n", pubkey_client);

  return pubkey_client;
}

void send_server_pubkey(void *data, size_t len)
{
  printf("[EH] Sending attester public key in clear:\n");

  if (PRINT_MESSAGE_BUFFERS)
    print_hex_data((unsigned char *)data, len);

  send_buffer((byte *)data, len);
}

encl_message_t wait_for_message()
{

  size_t len;

  void *buffer = recv_buffer(&len);

  printf("[EH] Got an encrypted message:\n");
  if (PRINT_MESSAGE_BUFFERS)
    print_hex_data((unsigned char *)buffer, len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

void send_report(void *buffer, size_t len)
{
  printf("[EH] Sending encrypted report:\n");

  if (PRINT_MESSAGE_BUFFERS)
    print_hex_data((unsigned char *)buffer, len);

  send_buffer((byte *)buffer, len);
}

void init_wolfSSL()
{

  /* Initialize wolfSSL */
  wolfSSL_Init();

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL)
  {
    printf("ERROR: failed to create WOLFSSL_CTX\n");
    exit(-1);
  }

  /*Load server certificates into WOLFSSL_CTX */
  if ((wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS)
  {
    printf("ERROR: failed to load %s, please check the file.\n",
           CERT_FILE);
    exit(-1);
  }

  /* Load server key into WOLFSSL_CTX */
  if ((wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS)
  {
    printf("ERROR: failed to load %s, please check the file.\n",
           KEY_FILE);
    exit(-1);
  }

  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL)
  {
    printf("ERROR: failed to create WOLFSSL object\n");
    exit(-1);
  }

  /* Attach wolfSSL to the socket */
  wolfSSL_set_fd(ssl, fd_clientsock);

  /* Establish TLS connection */
  if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS)
  {
    printf("wolfSSL_accept error\n");
    exit(-1);
  }

  printf("[EH] TLS connection correctly established\n");

  /* Read the client data into our buff array */
  /*memset(buff, 0, sizeof(buff));
  if ((wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1)
  {
    printf("ERROR: failed to read\n");
    exit(-1);
  }*/

  /* Print to stdout any data the client sends */
  // printf("Client: %s\n", buff);

  // const char *reply = "I hear ya fa shizzle!\n";

  /* Write our reply into buff */
  // memset(buff, 0, sizeof(buff));
  // memcpy(buff, reply, strlen(reply));

  // size_t len = strnlen(buff, sizeof(buff));
  /* Reply back to the client */
  /*if ((wolfSSL_write(ssl, buff, len)) != len)
  {
    printf("ERROR: failed to write\n");
    exit(-1);
  }*/

  /* Notify the client that the connection is ending */
  // wolfSSL_shutdown(ssl);
  // printf("Shutdown complete\n");

  /* Cleanup after this connection */
  // wolfSSL_free(ssl); /* Free the wolfSSL object              */
  // close(fd_clientsock);      /* Close the connection to the client   */
}

void init_network_wait()
{

  int fd_sock;
  struct sockaddr_in attester_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0)
  {
    printf("Failed to open socket\n");
    exit(-1);
  }
  memset(&attester_addr, 0, sizeof(attester_addr));
  attester_addr.sin_family = AF_INET;
  attester_addr.sin_addr.s_addr = INADDR_ANY;
  attester_addr.sin_port = htons(PORTNUM);
  if (bind(fd_sock, (struct sockaddr *)&attester_addr, sizeof(attester_addr)) < 0)
  {
    printf("Failed to bind socket\n");
    exit(-1);
  }

  /* Listen for a new connection, allow 2 pending connections */
  listen(fd_sock, 2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr *)&client_addr, &client_len);
  if (fd_clientsock < 0)
  {
    printf("No valid client socket\n");
    exit(-1);
  }

  printf("[EH] Got connection from remote client\n");
  init_wolfSSL();
}

int main(int argc, char **argv)
{

  /* Wait for network connection */
  init_network_wait();

  Keystone::Enclave enclave;
  Keystone::Params params;

  if (enclave.init(enc_path, runtime_path, params) != Keystone::Error::Success)
  {
    printf("HOST: Unable to start enclave\n");
    exit(-1);
  }

  edge_init(&enclave);

  Keystone::Error rval = enclave.run();
  printf("rval: %i\n", rval);

  return 0;
}
