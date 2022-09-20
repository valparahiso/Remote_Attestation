#ifndef _REGISTRAR_DB_OP_HPP_
#define _REGISTRAR_DB_OP_HPP_

#include <stdio.h>
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

nl::json get_pp_from_db();
nl::json check_pp_send_challenge(nl::json data_json);

#endif /*  _REGISTRAR_DB_OP_HPP_ */
