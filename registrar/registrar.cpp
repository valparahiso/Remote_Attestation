#include <pybind11/pybind11.h>
#include <nlohmann/json.hpp>
#include "./extern/pybind11_json_binding/include/pybind11_json/pybind11_json.hpp"
#include "pp_api.hpp"
#include <iostream>

namespace py = pybind11;
namespace nl = nlohmann;

nl::json register_node(const nl::json &data_json)
{
    return check_pp_send_challenge(data_json);
}

nl::json accept_node(const nl::json &data_json)
{
    return accept_node_db(data_json);
}

nl::json get_platform_providers()
{
    return get_pp_from_db();
}

/*nl::json register_eapp(const nl::json &data_json)
{
    return check_developer_send_challenge(data_json);
}*/

PYBIND11_MODULE(registrar, m)
{
    m.doc() = "My awesome module";

    m.def("register_node", &register_node, "pass py::object to a C++ function that takes an nlohmann::json");
    m.def("accept_node", &accept_node, "pass py::object to a C++ function that takes an nlohmann::json");
    m.def("get_platform_providers", &get_platform_providers, "return py::object from a C++ function that returns an nlohmann::json");
    m.def("register_eapp", &register_eapp, "pass py::object to a C++ function that takes an nlohmann::json");
}