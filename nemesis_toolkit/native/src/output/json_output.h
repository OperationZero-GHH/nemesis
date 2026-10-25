#pragma once
/**
 * @file json_output.h
 * @brief JSON serialization for scan results.
 */

#include "../core/scan_result.h"
#include <string>

namespace nemesis {

/**
 * Serialize a ScanResult to JSON string.
 * Compatible with the Nemesis Finding model format.
 */
std::string scan_result_to_json(const ScanResult& result, bool pretty = true);

/**
 * Serialize a ScanResult to a Nemesis-compatible JSON array of findings.
 * Each open port, OS match, traceroute hop, and script result becomes
 * a separate finding object.
 */
std::string scan_result_to_findings_json(const ScanResult& result, bool pretty = true);

/**
 * Write scan results to a JSON file.
 */
bool write_json_file(const ScanResult& result, const std::string& path, bool pretty = true);

} // namespace nemesis
