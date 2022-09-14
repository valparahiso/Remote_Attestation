#include <pybind11/pybind11.h> 
#include <nlohmann/json.hpp>

namespace py = pybind11;
namespace nl = nlohmann;

int add(int i, int j){
    return i+j;
}


PYBIND11_MODULE(registrar, m) {
    m.doc() = "pybind11 example plugin"; // optional module docstring

    m.def("add", &add, "A function that adds two numbers", py::arg("i"), py::arg("j")); 
}