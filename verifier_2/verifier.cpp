#include <pybind11/pybind11.h>
#include <nlohmann/json.hpp>
#include "./extern/pybind11_json_binding/include/pybind11_json/pybind11_json.hpp"
#include "./trusted_verifier/verifier_db_op.hpp"
#include <iostream>

namespace py = pybind11;
namespace nl = nlohmann;

nl::json register_node(const nl::json &data_json)
{
    return register_node_db(data_json);
}

PYBIND11_MODULE(verifier, m)
{
    m.doc() = "My awesome module";

    m.def("register_node", &register_node, "pass py::object to a C++ function that takes an nlohmann::json");
}