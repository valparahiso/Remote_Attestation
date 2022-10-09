#ifndef _DEVELOPER_API_HPP_
#define _DEVELOPER_API_HPP_

#include <stdio.h>
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

bool check_developer_pub_key(std::string developer_pub_key);
nl::json check_developer_send_challenge(nl::json data_json);
nl::json accept_eapp_db(nl::json data_json); 

#endif /*  _DEVELOPER_API_HPP_ */
