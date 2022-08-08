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

#define PORTNUM 8067
int fd_sock;
struct sockaddr_in server_addr;
struct hostent *server;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

void send_buffer(byte *buffer, size_t len)
{
  write(fd_sock, &len, sizeof(size_t));
  write(fd_sock, buffer, len);
}

byte *recv_buffer(size_t *len)
{
  ssize_t n_read = read(fd_sock, local_buffer, sizeof(size_t));
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
  n_read = read(fd_sock, reply, reply_size);
  if ((size_t) n_read != reply_size)
  {
    printf("[TC] Bad message size\n");
    // Shutdown
    trusted_verifier_exit();
  }

  *len = reply_size;
  return reply;
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

  /* Establish channel */
  trusted_verifier_init();

  /* Send pubkey */
  size_t pubkey_size;
  byte *pubkey = trusted_verifier_pubkey(&pubkey_size);
  send_buffer(pubkey, pubkey_size);

  /* Send nonce to avoid reply attacks TODO HERE*/
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
