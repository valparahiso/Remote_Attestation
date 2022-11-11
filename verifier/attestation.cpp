#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "trusted_verifier.hpp"
#include "attestation.hpp"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>

#define PORTNUM 1111
#define BUFFERLEN 4096
#define NUMCONNECTION 5

struct eapp
{
  int id;
  char eapp_path[32];
  uint16_t port;
};

struct attester
{
  int id;
  char hostname[32];
  uint16_t port;
  eapp eapps[8]; // can have maximum 8 eapps with maximum path size 32
};

int fd_sock;
byte local_buffer[BUFFERLEN];
attester my_attester;
int num_of_eapps = 0;
bool attester_exist = false;

int connections;

/* declare wolfSSL objects */
WOLFSSL_CTX *ctx;
WOLFSSL *ssl;

bool send_buffer(byte *buffer, size_t len)
{
  /* Send the message to the server */
  if ((wolfSSL_write(ssl, &len, sizeof(size_t))) != sizeof(size_t))
  {
    printf("ERROR: failed to write size of message\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    return false;
  }

  if ((wolfSSL_write(ssl, buffer, len)) != (int)len)
  {
    printf("ERROR: failed to write message for server\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    return false;
  }

  printf("Message correctly sent");
  return true;
}

byte *recv_buffer(size_t *len)
{
  ssize_t n_read;
  /* Read the server data into our buff array */
  n_read = wolfSSL_read(ssl, local_buffer, sizeof(size_t));

  if (n_read == 0)
  {
    printf("ERROR: failed to read message size\n");
    return (byte *)"ERROR";
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
    return (byte *)"ERROR";
  }

  if ((size_t)n_read != reply_size)
  {
    printf("Bad message size\n");
    return (byte *)"ERROR";
  }

  *len = reply_size;

  printf("Message correctly received\n");
  return reply;
}

bool init_wolfSSL()
{
  /* Initialize wolfSSL */
  if ((wolfSSL_Init()) != WOLFSSL_SUCCESS)
  {
    printf("ERROR: Failed to initialize the library\n");
    close(fd_sock);
    return false;
  }

  /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
  {
    printf("ERROR: failed to create WOLFSSL_CTX\n");
    close(fd_sock);
    return false;
  }

  /* Load client certificates into WOLFSSL_CTX */
  if ((wolfSSL_CTX_load_verify_locations(ctx, "../certs/CA/ca-cert.pem", NULL)) != SSL_SUCCESS)
  {
    printf("ERROR: failed to load %s, please check the file.\n",
           "./certs/ca-cert.pem");
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    return false;
  }

  /* Create a WOLFSSL object */
  if ((ssl = wolfSSL_new(ctx)) == NULL)
  {
    printf("ERROR: failed to create WOLFSSL object\n");
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    return false;
  }

  /* Attach wolfSSL to the socket */
  if ((wolfSSL_set_fd(ssl, fd_sock)) != WOLFSSL_SUCCESS)
  {
    printf("ERROR: Failed to set the file descriptor\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    return false;
  }

  /* Connect to wolfSSL on the server side */
  if ((wolfSSL_connect(ssl)) != SSL_SUCCESS)
  {
    printf("ERROR: failed to connect to wolfSSL\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    return false;
  }

  printf("TLS connection correctly set up\n");
  return true;
}

void close_wolfSSL()
{

  if (wolfSSL_shutdown(ssl) == SSL_FATAL_ERROR)
  {
    printf("Failed to shutdown the connection\n");
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(fd_sock);
    exit(-1);
  }

  wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
  wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
  wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
  close(fd_sock);
  printf("TLS connection shutted down correctly\n");
}

void str_to_uint16(const char *str, uint16_t *res)
{
  char *end;
  errno = 0;
  long val = strtol(str, &end, 10);
  *res = (uint16_t)val;
  return;
}

bool connect_to_attester(char *hostname, uint16_t port)
{
  printf("\nTrying to connect to %s . . .\n", hostname);
  struct sockaddr_in server_addr;
  struct hostent *server;
  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0)
  {
    printf("No socket\n");
    return false;
  }

  server = gethostbyname(hostname);
  if (server == NULL)
  {
    printf("Can't get host\n");
    return false;
  }

  server_addr.sin_family = AF_INET;
  memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
  server_addr.sin_port = htons(port);
  if (connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    printf("Can't connect\n");
    return false;
  }

  connections = 0;
  printf("Connected to %s\n", hostname);
  return true;
}

static int get_attester_callback(void *notUsed, int count, char **data, char **columns)
{
  attester_exist = true;
  for (int idx = 0; idx < count; idx++)
  {
    if (!strcmp(columns[idx], "hostname"))
    {
      for (int i = 0; i < (int)strlen(data[idx]); i++)
        my_attester.hostname[i] = data[idx][i];
    }
    else if (!strcmp(columns[idx], "port"))
    {
      char *port_str = data[idx];
      uint16_t port_uint16;

      str_to_uint16(port_str, &port_uint16);
      my_attester.port = port_uint16;
    }
    else if (!strcmp(columns[idx], "id"))
    {
      my_attester.id = atoi(data[idx]);
    }
  }

  return 0;
}

bool get_attester(std::string uuid)
{
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;
  std::string sql = "SELECT id, hostname, port from attestors WHERE uuid='" + uuid + "'";
  attester_exist = false;
  /* Open database */
  rc = sqlite3_open("./db/gvalues.db", &db);

  if (rc)
  {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return false;
  }

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql.c_str(), get_attester_callback, NULL, &zErrMsg);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    return false;
  }

  sqlite3_close(db);
  return attester_exist;
}

static int get_eapps_callback(void *notUsed, int count, char **data, char **columns)
{
  for (int idx = 0; idx < count; idx++)
  {
    if (!strcmp(columns[idx], "path"))
    {
      for (int j = 0; j < (int)strlen(data[idx]); j++)
        my_attester.eapps[num_of_eapps].eapp_path[j] = data[idx][j];

      my_attester.eapps[num_of_eapps].eapp_path[strlen(data[idx])] = '\0';
    }
    else if (!strcmp(columns[idx], "id"))
    {
      my_attester.eapps[num_of_eapps].id = atoi(data[idx]);
    }
    else if (!strcmp(columns[idx], "port"))
    {
      char *port_str = data[idx];
      uint16_t port_uint16;

      str_to_uint16(port_str, &port_uint16);
      my_attester.eapps[num_of_eapps].port = port_uint16;
    }
  }

  num_of_eapps++;

  return 0;
}

bool get_eapps(int id)
{
  sqlite3 *db;
  char *zErrMsg = 0;
  int rc;
  char sql[256];
  num_of_eapps = 0;

  /* Open database */
  rc = sqlite3_open("./db/gvalues.db", &db);

  if (rc)
  {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    return false;
  }

  /* Create SQL statement */
  sprintf(sql, "SELECT path, id, port from eapps WHERE attestor=%d", id);
  printf("sql: %s", sql);

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, get_eapps_callback, nullptr, &zErrMsg);

  if (rc != SQLITE_OK)
  {
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
    return false;
  }

  sqlite3_close(db);
  return true;
}

nl::json attest_node_db(const std::string uuid)
{
  nl::json bad_res = {{"Error", "Internal Server Error"}, {"Code", "500"}};
  if (!get_attester(uuid) || !get_eapps(my_attester.id)) // get eapps to attest
  {
    return bad_res;
  }

  for (int q = 0; q < num_of_eapps; q++)
  {

    for (int i = 0; i < NUMCONNECTION; i++)
    {
      bool connected = connect_to_attester(my_attester.hostname, my_attester.eapps[q].port);
      if (connected)
        break;
      else if (i == NUMCONNECTION - 1)
      {
        printf("\nUnable create a socket with %s, updating the status\n", my_attester.hostname);
        update_status_and_timestamp(true, "NO_CONNECTION", my_attester.id);
        return bad_res;
      }
    }

    if (!init_wolfSSL())
    {
      printf("Unable to set up a TLS connection with %s, updating the status and passing to next attester\n");
      update_status_and_timestamp(true, "NO_TLS_CONNECTION", my_attester.id);
      return bad_res;
    }

    if (!update_status_and_timestamp(true, "TLS_CONNECTION", my_attester.id))
    {
      return bad_res;
    }

    // trusted_verifier_init(); // Generate verifier keypair using libsodium

    // for (int j = 0; j < num_of_eapps; j++)
    //{
    printf("\nTrying to send eapp path to attest. . .\n");
    if (!send_buffer((byte *)my_attester.eapps[q].eapp_path, strlen(my_attester.eapps[q].eapp_path)))
    {
      return bad_res;
    }

    printf("\nStarting attesting the eapp with path %s. . .\n", my_attester.eapps[q].eapp_path);

    /*if (!exchange_keys_and_establish_channel()) // Send verifier pubkey, and receive attester pubkey to establish an encrypted channel
    {
      printf("Passing to the next eapp\n");
      update_status_and_timestamp(false, "VALIDATION_ERROR", my_attester.eapps[j].id);
      continue;
    }*/

    if (!send_nonce()) // Send nonce to avoid reply attacks
    {
      return bad_res;
    }

    printf("\nTrying to receive report from the attester. . .\n");
    size_t report_size;
    byte *report_buffer = recv_buffer(&report_size); // Get report from the attester

    if (!strcmp((char *)report_buffer, "ERROR"))
    {
      printf("Passing to the next eapp\n");
      update_status_and_timestamp(false, "VALIDATION_ERROR", my_attester.eapps[q].id);
      continue;
    }

    if (!trusted_verifier_attest_report(report_buffer, report_size, my_attester.id, my_attester.eapps[q].id))
    { // Decrypt and attest the received report
      printf("Passing to the next eapp\n");
      update_status_and_timestamp(false, "VALIDATION_ERROR", my_attester.eapps[q].id);
      free(report_buffer);
      continue;
    }

    free(report_buffer);
    //}

    printf("\nTrying to send close connection message to the attester. . .\n");
    send_buffer((byte *)"CLOSE", strlen("CLOSE"));

    printf("\nTrying to close TLS connection. . .\n");
    close_wolfSSL(); // Closing the TLS connection 
  }

  return {{"Message", "Node Correctly Attested, Chek Logs in Verifier DB"}, {"Code", "200"}};
}

/*int main(int argc, char *argv[])
{


  //TODO eliminare il main ricompilare tutto come dio comanda e creare api con flask

  size_t report_size;
  byte *report_buffer;

  get_attesters();

  for (int i = 0; i < num_of_attesters; i++)
  {
    get_eapps(attesters[i].id, i);
    connections = NUMCONNECTION;

    while (connections > 0)
    {
      connect_to_attester(attesters[i].hostname, attesters[i].port); // Connect to the attester
      connections--;
    }

    if (connections == 0)
    {
      printf("\nUnable create a socket with %s, updating the status and passing to next attester\n", attesters[i].hostname);
      update_status_and_timestamp(true, "NO_CONNECTION", attesters[i].id);
    }
    else
    {
      if (!init_wolfSSL())
      {
        printf("Unable to set up a TLS connection with %s, updating the status and passing to next attester\n");
        update_status_and_timestamp(true, "NO_TLS_CONNECTION", attesters[i].id);
        continue;
      }

      update_status_and_timestamp(true, "TLS_CONNECTION", attesters[i].id);

      trusted_verifier_init(); // Generate verifier keypair using libsodium

      for (int j = 0; j < num_of_eapps; j++)
      {
        printf("\nTrying to send eapp path to attest. . .\n");
        send_buffer((byte *)attesters[i].eapps[j].eapp_path, strlen(attesters[i].eapps[j].eapp_path));

        printf("\nStarting attesting the eapp with path %s. . .\n", attesters[i].eapps[j].eapp_path);

        if (!exchange_keys_and_establish_channel()) // Send verifier pubkey, and receive attester pubkey to establish an encrypted channel
        {
          printf("Passing to the next eapp\n");
          update_status_and_timestamp(false, "VALIDATION_ERROR", attesters[i].eapps[j].id);
          continue;
        }

        send_nonce(); // Send nonce to avoid reply attacks

        printf("\nTrying to receive encrypted report from the attester. . .\n");
        report_buffer = recv_buffer(&report_size); // Get encrypted report from the attester

        if (!strcmp((char *)report_buffer, "ERROR"))
        {
          printf("Passing to the next eapp\n");
          update_status_and_timestamp(false, "VALIDATION_ERROR", attesters[i].eapps[j].id);
          continue;
        }

        if (!trusted_verifier_attest_report(report_buffer, report_size, attesters[i].id, attesters[i].eapps[j].id))
        { // Decrypt and attest the received report
          printf("Passing to the next eapp\n");
          update_status_and_timestamp(false, "VALIDATION_ERROR", attesters[i].eapps[j].id);
          free(report_buffer);
          continue;
        }

        free(report_buffer);
      }

      printf("\nTrying to send close connection message to the attester. . .\n");
      send_buffer((byte *)"CLOSE", strlen("CLOSE"));

      printf("\nTrying to close TLS connection. . .\n");
      close_wolfSSL(); // Closing the TLS connection
    }

    num_of_eapps = 0;
  }

  return 0;
}*/
