#include <sqlite3.h>
#include <nlohmann/json.hpp>

namespace nl = nlohmann;

nl::json register_node_db(nl::json attester_data);
nl::json register_eapp_db(nl::json eapp_data);