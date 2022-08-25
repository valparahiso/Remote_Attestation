#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "trusted_verifier.h"
#include "verifier.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/stat.h>
#include <stdbool.h>

#define PORTNUM 1111
#define BUFFERLEN 4096

int fd_sock;
byte local_buffer[BUFFERLEN];

/* declare wolfSSL objects */
WOLFSSL_CTX *ctx;
WOLFSSL *ssl;

void send_buffer(byte *buffer, size_t len)
{
  /* Send the message to the server */
  if ((wolfSSL_write(ssl, &len, sizeof(size_t))) != sizeof(size_t))
  {
    printf("ERROR: failed to write size of message\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  if ((wolfSSL_write(ssl, buffer, len)) != (int) len)
  {
    printf("ERROR: failed to write message for server\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  printf("Message correctly sent\n");
}

byte *recv_buffer(size_t *len)
{
  ssize_t n_read;
  /* Read the server data into our buff array */
  n_read = wolfSSL_read(ssl, local_buffer, sizeof(size_t));

  if (n_read == 0)
  {
    printf("ERROR: failed to read message size\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  if (n_read != sizeof(size_t))
  {
    // Shutdown
    printf("Invalid message header\n");
    trusted_verifier_exit();
  }

  size_t reply_size = *(size_t *)local_buffer;
  byte *reply = (byte *)malloc(reply_size);
  if (reply == NULL)
  {
    // Shutdown
    printf("Message too large\n");
    trusted_verifier_exit();
  }

  n_read = wolfSSL_read(ssl, reply, reply_size);
  if (n_read == 0)
  {
    printf("ERROR: failed to read server message\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  if ((size_t)n_read != reply_size)
  {
    printf("Bad message size\n");
    // Shutdown
    trusted_verifier_exit();
  }

  *len = reply_size;

  printf("Message correctly received\n");
  return reply;
}

void init_wolfSSL()
{

  /* Initialize wolfSSL */
  if ((wolfSSL_Init()) != WOLFSSL_SUCCESS)
  {
    printf("ERROR: Failed to initialize the library\n");
    close(fd_sock);
    exit(-1);
  }

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
  {
    printf("ERROR: failed to create WOLFSSL_CTX\n");
    close(fd_sock);
    exit(-1);
  }

  /* Load client certificates into WOLFSSL_CTX */
  if ((wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", NULL)) != SSL_SUCCESS)
  {
    printf("ERROR: failed to load %s, please check the file.\n",
           "./certs/ca-cert.pem");
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL)
  {
    printf("ERROR: failed to create WOLFSSL object\n");
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  /* Attach wolfSSL to the socket */
  if ((wolfSSL_set_fd(ssl, fd_sock)) != WOLFSSL_SUCCESS)
  {
    printf("ERROR: Failed to set the file descriptor\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  /* Connect to wolfSSL on the server side */
  if ((wolfSSL_connect(ssl)) != SSL_SUCCESS)
  {
    printf("ERROR: failed to connect to wolfSSL\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }
}

void connect_to_attester(char *hostname)
{
  printf("\nTrying to connect to %s . . .\n", hostname);
  struct sockaddr_in server_addr;
  struct hostent *server;
  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0)
  {
    printf("No socket\n");
    exit(-1);
  }

  server = gethostbyname(hostname);
  if (server == NULL)
  {
    printf("Can't get host\n");
    exit(-1);
  }

  server_addr.sin_family = AF_INET;
  memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
  server_addr.sin_port = htons(PORTNUM);
  if (connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    printf("Can't connect\n");
    exit(-1);
  }

  printf("Connected to %s\n", hostname);
}

int main(int argc, char *argv[])
{

  size_t report_size;
  byte *report_buffer;

  if (argc < 2)
  {
    printf("Usage %s hostname\n", argv[0]);
    exit(-1);
  }

  connect_to_attester(argv[1]); // Connect to the attester

  init_wolfSSL(); // Set up the TLS connection on the socket

  trusted_verifier_init(); // Generate verifier keypair using libsodium

  exchange_keys_and_establish_channel(); // Send verifier pubkey, and receive attester pubkey to establish an encrypted channel

  send_nonce(); // Send nonce to avoid reply attacks

  printf("\nTrying to receive encrypted report from the attester. . .\n");
  report_buffer = recv_buffer(&report_size); // Get encrypted report from the attester

  trusted_verifier_attest_report(report_buffer, report_size); // Decrypt and attest the received report

  free(report_buffer);

  /* Send/recv messages */
  for (;;)
  {
    printf("Either type message for remote word count, or q to quit\n> ");

    memset(local_buffer, 0, BUFFERLEN);
    fgets((char *)local_buffer, BUFFERLEN - 1, stdin);
    printf("\n");

    /* Handle quit */
    if (local_buffer[0] == 'q' && (local_buffer[1] == '\0' || local_buffer[1] == '\n'))
    {
      send_exit_message();
      close(fd_sock);
      exit(0);
    }
    else
    {
      send_wc_message((char *)local_buffer);
      size_t reply_size;
      byte *reply = recv_buffer(&reply_size);
      trusted_verifier_read_reply(reply, reply_size);
      free(reply);
    }
  }
  return 0;
}
