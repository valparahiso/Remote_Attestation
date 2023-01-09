#include <pybind11/pybind11.h>
#include <nlohmann/json.hpp>
#include "./extern/pybind11_json_binding/include/pybind11_json/pybind11_json.hpp"
#include "registration.hpp"
#include "attestation.hpp"
#include <iostream>

namespace py = pybind11;
namespace nl = nlohmann;

nl::json register_node(const nl::json &data_json)
{
    return register_node_db(data_json);
}

nl::json register_eapp(const nl::json &data_json)
{
    return register_eapp_db(data_json);
}

nl::json attest_node(const std::string uuid) 
{
    return attest_node_db(uuid);
}


PYBIND11_MODULE(verifier, m)
{
    m.doc() = "My awesome module";

    m.def("register_node", &register_node, "pass py::object to a C++ function that takes an nlohmann::json");
    m.def("register_eapp", &register_eapp, "pass py::object to a C++ function that takes an nlohmann::json");
    m.def("attest_node", &attest_node, "pass py::object to a C++ function that takes an nlohmann::json");
}