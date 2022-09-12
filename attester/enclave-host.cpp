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
    printf("[Enclave Host] ERROR: failed to write size of message\n");
    exit(-1);
  }

  if ((wolfSSL_write(ssl, buffer, len)) != len)
  {
    printf("[Enclave Host] ERROR: failed to write message for verifier\n");
    exit(-1);
  }

  printf("[Enclave Host] Message correctly sent to the verifier\n");
}

byte *recv_buffer(size_t *len)
{
  /* Read the client data into our buff array */
  memset(local_buffer, 0, sizeof(local_buffer));
  if ((wolfSSL_read(ssl, local_buffer, sizeof(size_t))) == 0)
  {
    printf("[Enclave Host]  ERROR: failed to read length\n");
    exit(-1);
  }
  // read(fd_clientsock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t *)local_buffer;
  byte *reply = (byte *)malloc(reply_size + 1);

  if ((wolfSSL_read(ssl, reply, reply_size)) == -1)
  {
    printf("[Enclave Host]  ERROR: failed to read reply\n");
    exit(-1);
  }
  // read(fd_clientsock, reply, reply_size);
  *len = reply_size;
  reply[reply_size] = '\0';
  printf("[Enclave Host] Message correctly received from the verifier");

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
  if (str[0] == '\n')
    printf("\n[Enclave Trusted App] %s", str + 1);
  else
    printf("[Enclave Trusted App] %s", str);
  return strlen(str);
}

void print_value(unsigned long val)
{
  printf("[Enclave Trusted App] value: %u\n", val);
  return;
}

void send_reply(void *data, size_t len)
{
  send_buffer((byte *)data, len);
}

void *wait_for_client_pubkey()
{
  size_t len;
  byte *pubkey_client = recv_buffer(&len);
  return pubkey_client;
}

void send_server_pubkey(void *data, size_t len)
{
  send_buffer((byte *)data, len);
}

encl_message_t wait_for_message()
{
  size_t len;
  void *buffer = recv_buffer(&len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

void send_report(void *buffer, size_t len)
{
  send_buffer((byte *)buffer, len);
}

void init_wolfSSL()
{

  printf("\n[Enclave Host] Trying to create a TLS connection over the created socket\n");
  /* Initialize wolfSSL */
  wolfSSL_Init();

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL)
  {
    printf("[Enclave Host] ERROR: failed to create WOLFSSL_CTX\n");
    exit(-1);
  }

  /*Load server certificates into WOLFSSL_CTX */
  if ((wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS)
  {
    printf("[Enclave Host] ERROR: failed to load %s, please check the file.\n",
           CERT_FILE);
    exit(-1);
  }

  /* Load server key into WOLFSSL_CTX */
  if ((wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS)
  {
    printf("[Enclave Host] ERROR: failed to load %s, please check the file.\n",
           KEY_FILE);
    exit(-1);
  }

  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL)
  {
    printf("[Enclave Host] ERROR: failed to create WOLFSSL object\n");
    exit(-1);
  }

  /* Attach wolfSSL to the socket */
  wolfSSL_set_fd(ssl, fd_clientsock);

  /* Establish TLS connection */
  if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS)
  {
    printf("[Enclave Host] wolfSSL_accept error\n");
    exit(-1);
  }

  printf("[Enclave Host]  TLS connection correctly established\n");
}

void init_network_wait()
{

  printf("[Enclave Host] Waiting for connection from verifier. . .\n");
  int fd_sock;
  struct sockaddr_in attester_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0)
  {
    printf("Enclave host failed to open socket\n");
    exit(-1);
  }
  memset(&attester_addr, 0, sizeof(attester_addr));
  attester_addr.sin_family = AF_INET;
  attester_addr.sin_addr.s_addr = INADDR_ANY;
  attester_addr.sin_port = htons(PORTNUM);
  if (bind(fd_sock, (struct sockaddr *)&attester_addr, sizeof(attester_addr)) < 0)
  {
    printf("Enclave Host failed to bind socket\n");
    exit(-1);
  }

  /* Listen for a new connection, allow 2 pending connections */
  listen(fd_sock, 2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr *)&client_addr, &client_len);
  if (fd_clientsock < 0)
  {
    printf("Enclave host has no valid client socket\n");
    exit(-1);
  }
  printf("[Enclave Host] Got connection from remote client\n");
}

void close_wolfSSL()
{
  if (wolfSSL_shutdown(ssl) == SSL_FATAL_ERROR)
  {
    printf("Failed to shutdown the connection complete\n");
    exit(-1);
  }

  wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
  wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
  printf("[Enclave Host] Shutdown completed\n");
}

int main(int argc, char **argv)
{
  /* Wait for network connection */
  init_network_wait();

  init_wolfSSL();

  while (1)
  {
    printf("\n[Enclave Host] Trying to receive the eapp path to attest . . .\n");
    size_t len;
    char *eapp_path = (char *)recv_buffer(&len);

    if(!strcmp(eapp_path, "CLOSE")){
      printf("\n[Enclave Host] Received closing message, exiting . . .\n");
      return 0; 
    }

    Keystone::Enclave enclave;
    Keystone::Params params;

    if (enclave.init(eapp_path, runtime_path, params) != Keystone::Error::Success)
    {
      printf("[Enclave Host] Unable to start enclave\n");
      exit(-1);
    }

    printf("\n[Enclave Host] Starting the enclave . . .\n");
    edge_init(&enclave);

    Keystone::Error rval = enclave.run();
    printf("[Enclave Host] Enclave returned: %i\n", rval);
  }
  return 0;
}
