/**
 * @file python_module.cpp
 * @brief pybind11 module bindings for NemesisScanEngine.
 */

#if __has_include(<pybind11/pybind11.h>)
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../core/engine.h"
#include "../core/config.h"
#include "../output/json_output.h"

namespace py = pybind11;
using namespace nemesis;

PYBIND11_MODULE(nemesis_scan, m) {
    m.doc() = "Nemesis C++ High-Performance Port Scanner Engine";

    py::enum_<PortState>(m, "PortState")
        .value("Open", PortState::Open)
        .value("Closed", PortState::Closed)
        .value("Filtered", PortState::Filtered)
        .value("Unfiltered", PortState::Unfiltered)
        .value("OpenFiltered", PortState::OpenFiltered)
        .value("ClosedFiltered", PortState::ClosedFiltered)
        .value("Unknown", PortState::Unknown);

    py::enum_<ScanType>(m, "ScanType")
        .value("TcpSyn", ScanType::TcpSyn)
        .value("TcpConnect", ScanType::TcpConnect)
        .value("TcpAck", ScanType::TcpAck)
        .value("TcpWindow", ScanType::TcpWindow)
        .value("TcpMaimon", ScanType::TcpMaimon)
        .value("TcpNull", ScanType::TcpNull)
        .value("TcpFin", ScanType::TcpFin)
        .value("TcpXmas", ScanType::TcpXmas)
        .value("TcpCustom", ScanType::TcpCustom)
        .value("Udp", ScanType::Udp)
        .value("SctpInit", ScanType::SctpInit)
        .value("SctpCookieEcho", ScanType::SctpCookieEcho)
        .value("IpProtocol", ScanType::IpProtocol)
        .value("Idle", ScanType::Idle)
        .value("FtpBounce", ScanType::FtpBounce)
        .value("ListScan", ScanType::ListScan)
        .value("PingScan", ScanType::PingScan);

    py::class_<PortResult>(m, "PortResult")
        .def_readonly("port", &PortResult::port)
        .def_readonly("protocol", &PortResult::protocol)
        .def_readonly("state", &PortResult::state)
        .def_readonly("reason", &PortResult::reason)
        .def_readonly("service", &PortResult::service)
        .def_readonly("product", &PortResult::product)
        .def_readonly("version", &PortResult::version)
        .def_readonly("extra_info", &PortResult::extra_info)
        .def_readonly("cpe", &PortResult::cpe)
        .def_readonly("banner", &PortResult::banner)
        .def_readonly("is_ssl", &PortResult::is_ssl);

    py::class_<HostResult>(m, "HostResult")
        .def_readonly("ip", &HostResult::ip)
        .def_readonly("hostname", &HostResult::hostname)
        .def_readonly("is_up", &HostResult::is_up)
        .def_readonly("status_reason", &HostResult::status_reason)
        .def_readonly("latency_ms", &HostResult::latency_ms)
        .def_readonly("ports", &HostResult::ports);

    py::class_<ScanResult>(m, "ScanResult")
        .def_readonly("scanner", &ScanResult::scanner)
        .def_readonly("scanner_version", &ScanResult::scanner_version)
        .def_readonly("start_time", &ScanResult::start_time)
        .def_readonly("end_time", &ScanResult::end_time)
        .def_readonly("elapsed_seconds", &ScanResult::elapsed_seconds)
        .def_readonly("hosts_total", &ScanResult::hosts_total)
        .def_readonly("hosts_up", &ScanResult::hosts_up)
        .def_readonly("hosts_down", &ScanResult::hosts_down)
        .def_readonly("hosts", &ScanResult::hosts)
        .def("to_json", [](const ScanResult& r, bool pretty) {
            return scan_result_to_json(r, pretty);
        }, py::arg("pretty") = true)
        .def("to_findings_json", [](const ScanResult& r, bool pretty) {
            return scan_result_to_findings_json(r, pretty);
        }, py::arg("pretty") = false);

    py::class_<ScanConfig>(m, "ScanConfig")
        .def(py::init<>())
        .def_readwrite("targets", &ScanConfig::targets)
        .def_readwrite("target_file", &ScanConfig::target_file)
        .def_readwrite("scan_type", &ScanConfig::scan_type)
        .def_readwrite("port_spec", &ScanConfig::port_spec)
        .def_readwrite("fast_scan", &ScanConfig::fast_scan)
        .def_readwrite("top_ports", &ScanConfig::top_ports)
        .def_readwrite("all_ports", &ScanConfig::all_ports)
        .def_readwrite("service_detect", &ScanConfig::service_detect)
        .def_readwrite("version_intensity", &ScanConfig::version_intensity)
        .def_readwrite("os_detect", &ScanConfig::os_detect)
        .def_readwrite("skip_discovery", &ScanConfig::skip_discovery)
        .def_readwrite("concurrency", &ScanConfig::concurrency);

    py::class_<NemesisScanEngine>(m, "NemesisScanEngine")
        .def(py::init<>())
        .def("scan", &NemesisScanEngine::scan, py::arg("config"), py::call_guard<py::gil_scoped_release>())
        .def("cancel", &NemesisScanEngine::cancel)
        .def("progress", &NemesisScanEngine::progress)
        .def("is_scanning", &NemesisScanEngine::is_scanning)
        .def_static("has_raw_socket_privilege", &NemesisScanEngine::has_raw_socket_privilege)
        .def_static("list_interfaces", &NemesisScanEngine::list_interfaces)
        .def_static("version", &NemesisScanEngine::version);
}
#endif
