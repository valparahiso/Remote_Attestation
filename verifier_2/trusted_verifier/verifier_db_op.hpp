#ifndef _VERIFIER_DB_OP_HPP_
#define _VERIFIER_DB_OP_HPP_
#include "trusted_verifier.hpp"
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

void send_buffer(byte *buffer, size_t len);
byte *recv_buffer(size_t *len);
void connect_to_attester(char *hostname, uint16_t port);
void str_to_uint16(const char *str, uint16_t *res);
void close_wolfSSL();
void get_attesters();
void get_eapps(int id, int i);
nl::json register_node_db(nl::json attester_data);

#endif /* _VERIFIER_DB_OP_HPP_ */
