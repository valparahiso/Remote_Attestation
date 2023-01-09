#ifndef _OPENSSL_OP_HPP_
#define _OPENSSL_OP_HPP_

#include <stdio.h>
#include <string>
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

int calcDecodeLength(const char *b64input);
size_t Base64Encode(const char *buffer, char **b64text, size_t buffer_size);
int Base64Decode(char *b64message, char **buffer);
bool generate_challenge(unsigned char *challenge);
bool encrypt_challenge(unsigned char *challenge, std::string pp_pub_key);
bool send_values_to_verifier(std::string url, nl::json data);

#endif /*  _OPENSSL_OP_HPP_ */
