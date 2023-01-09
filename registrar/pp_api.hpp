#ifndef _PP_API_HPP_
#define _PP_API_HPP_

#include <stdio.h>
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

nl::json get_pp_from_db();
nl::json check_pp_send_challenge(nl::json data_json);
nl::json accept_node_db(nl::json data_json);

#endif /*  _PP_API_HPP_ */
