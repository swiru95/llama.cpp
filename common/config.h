#pragma once

#include "arg.h"
#include <functional>
#include <string>
#include <vector>

// Translate a YAML config file into a flat list of CLI-equivalent tokens
// (e.g. {"--ctx-size","4096","--api-key","k1,k2"}). Throws std::runtime_error
// with a clear, single-line message on any failure (malformed YAML, non-mapping
// root, unknown key, bad value shape) so the caller aborts startup (fail closed).
// `lookup` returns the registered common_arg for a flag string, or nullptr.
// F012c: out_policy_json is filled with the JSON-serialized auth_policy mapping
// if present (or left empty if absent).
std::vector<std::string> common_config_to_args(
    const std::string & path,
    const std::function<const common_arg *(const std::string &)> & lookup,
    std::string & out_policy_json);
