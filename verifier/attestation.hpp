#ifndef _ATTESTATION_HPP_
#define _ATTESTATION_HPP_
#include "trusted_verifier.hpp"
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

bool send_buffer(byte *buffer, size_t len);
byte *recv_buffer(size_t *len);
bool connect_to_attester(char *hostname, uint16_t port);
void str_to_uint16(const char *str, uint16_t *res);
void close_wolfSSL();
nl::json attest_node_db(const std::string uuid);

#endif /* _ATTESTATION_HPP_ */
