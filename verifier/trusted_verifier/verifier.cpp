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
int fd_sock;
struct sockaddr_in server_addr;
struct hostent *server;

#define BUFFERLEN 4096
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

  if ((wolfSSL_write(ssl, buffer, len)) != len)
  {
    printf("ERROR: failed to write message for server\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }
  // write(fd_sock, &len, sizeof(size_t));
  // write(fd_sock, buffer, len);
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
    printf("[TC] Invalid message header\n");
    trusted_verifier_exit();
  }

  size_t reply_size = *(size_t *)local_buffer;
  byte *reply = (byte *)malloc(reply_size);
  if (reply == NULL)
  {
    // Shutdown
    printf("[TC] Message too large\n");
    trusted_verifier_exit();
  }

  n_read = wolfSSL_read(ssl, reply, reply_size);
  if ( n_read == 0)
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
    printf("[TC] Bad message size\n");
    // Shutdown
    trusted_verifier_exit();
  }

  *len = reply_size;
  return reply;
}

void init_wolfSSL()
{
  /*---------------------------------*/
  /* Start of wolfSSL initialization and configuration */
  /*---------------------------------*/
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

  /* Send the message to the server */
  /*if ((wolfSSL_write(ssl, buff, len)) != len)
  {
    printf("ERROR: failed to write entire message\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
  // wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  // wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
  // close(fd_sock);
  // exit(-1);
  //}

  /* Read the server data into our buff array */
  /*memset(buff, 0, sizeof(buff));
  if ((wolfSSL_read(ssl, buff, sizeof(buff) - 1)) == -1)
  {
    printf("ERROR: failed to read\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
  // wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  // wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
  // close(fd_sock);
  // exit(-1);
  //}
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    printf("Usage %s hostname\n", argv[0]);
    exit(-1);
  }

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0)
  {
    printf("No socket\n");
    exit(-1);
  }
  server = gethostbyname(argv[1]);
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

  printf("[TC] Connected to enclave host!\n");

  init_wolfSSL();

  // genero chiavi pubblica e privata per il verifier
  trusted_verifier_init();

  /* Send verifier pubkey, and receive attester pubkey to establish an encrypted channel */
  exchange_keys_and_establish_channel();

  /* Send nonce to avoid reply attacks*/
  send_nonce();

  size_t report_size;
  byte *report_buffer = recv_buffer(&report_size);
  trusted_verifier_get_report(report_buffer);
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
