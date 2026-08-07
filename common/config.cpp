#include "config.h"
#include "preset.h"
#include "common.h"
#include "log.h"

#include <fkYAML/node.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <set>

static std::string normalize_key(const std::string & key) {
    std::string result = key;
    std::replace(result.begin(), result.end(), '_', '-');
    return result;
}

static std::string scalar_to_token(const fkyaml::node & node) {
    if (node.is_null()) {
        throw std::runtime_error("config: null value is not allowed");
    } else if (node.is_boolean()) {
        return node.get_value<bool>() ? "true" : "false";
    } else if (node.is_integer()) {
        return std::to_string(node.get_value<int64_t>());
    } else if (node.is_float_number()) {
        return std::to_string(node.get_value<double>());
    } else if (node.is_string()) {
        return node.get_value<std::string>();
    }
    throw std::runtime_error("config: unsupported scalar type");
}

// Convert fkYAML node to nlohmann::json, preserving YAML 1.2 scalar types
// (bool->JSON bool, int->JSON number, string->JSON string, null->JSON null)
static nlohmann::json fkyaml_to_json(const fkyaml::node & node) {
    if (node.is_null()) {
        return nlohmann::json(nullptr);
    } else if (node.is_boolean()) {
        return nlohmann::json(node.get_value<bool>());
    } else if (node.is_integer()) {
        return nlohmann::json(node.get_value<int64_t>());
    } else if (node.is_float_number()) {
        return nlohmann::json(node.get_value<double>());
    } else if (node.is_string()) {
        return nlohmann::json(node.get_value<std::string>());
    } else if (node.is_sequence()) {
        nlohmann::json arr = nlohmann::json::array();
        for (size_t i = 0; i < node.size(); ++i) {
            arr.push_back(fkyaml_to_json(node[i]));
        }
        return arr;
    } else if (node.is_mapping()) {
        nlohmann::json obj = nlohmann::json::object();
        for (auto it = node.begin(); it != node.end(); ++it) {
            const auto & key_node = it.key();
            if (!key_node.is_string()) {
                throw std::runtime_error("config: auth_policy keys must be strings");
            }
            std::string key = key_node.get_value<std::string>();
            obj[key] = fkyaml_to_json(it.value());
        }
        return obj;
    }
    throw std::runtime_error("config: unsupported YAML type in auth_policy");
}

std::vector<std::string> common_config_to_args(
    const std::string & path,
    const std::function<const common_arg *(const std::string &)> & lookup,
    std::string & out_policy_json) {

    out_policy_json = "";  // Initialize output parameter

    if (path.empty()) {
        throw std::runtime_error("config: path is empty");
    }

    // Read file
    std::ifstream file(path);
    if (!file.good()) {
        throw std::runtime_error(string_format("config: failed to open file: %s", path.c_str()));
    }

    std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (contents.empty()) {
        throw std::runtime_error("config: file is empty");
    }

    // Parse YAML
    fkyaml::node doc;
    try {
        doc = fkyaml::node::deserialize(contents);
    } catch (const fkyaml::exception & e) {
        throw std::runtime_error(string_format("config: malformed YAML: %s", e.what()));
    }

    // Detect multi-document stream: if the YAML contains "---" at document start, it's multi-doc
    // fkyaml::node::deserialize only parses the first document, but we should reject
    // if there are explicit document separators (---) indicating a multi-document stream
    if (contents.find("---") != std::string::npos) {
        // Be conservative: if we see ---, it might be a multi-document stream
        // Try to parse all docs and if there's more than one, reject
        try {
            auto docs = fkyaml::node::deserialize_docs(contents);
            if (docs.size() > 1) {
                throw std::runtime_error("config: multi-document YAML stream not allowed (exactly one document required)");
            }
        } catch (const fkyaml::exception &) {
            // If deserialize_docs fails, it's likely invalid YAML, which is caught below
        }
    }

    // Verify document root is a mapping
    if (!doc.is_mapping()) {
        throw std::runtime_error("config: document root must be a mapping");
    }

    // Check for duplicate keys: fkyaml should reject these during parsing
    // but we do an extra check in case the library behavior changes
    std::set<std::string> seen_keys;

    // Populate preset options map
    common_preset preset;
    preset.name = "config";

    for (auto it = doc.begin(); it != doc.end(); ++it) {
        const auto & key_node = it.key();
        const auto & value_node = it.value();

        if (!key_node.is_string()) {
            throw std::runtime_error("config: non-string key in mapping");
        }

        std::string key = key_node.get_value<std::string>();

        // Check for duplicate keys
        if (!seen_keys.insert(key).second) {
            throw std::runtime_error(string_format("config: duplicate key '%s'", key.c_str()));
        }

        // Check for merge keys (<<) which we do not support (billion-laughs prevention)
        if (key == "<<") {
            throw std::runtime_error("config: YAML merge keys (<<) are not allowed");
        }

        // Check for anchors/aliases (these would indicate alias expansion)
        if (key_node.is_anchor() || key_node.is_alias()) {
            throw std::runtime_error("config: YAML anchors/aliases are not allowed");
        }
        if (value_node.is_anchor() || value_node.is_alias()) {
            throw std::runtime_error("config: YAML anchors/aliases are not allowed");
        }

        // Special case: nested config is not allowed
        if (key == "config" || key == "c") {
            throw std::runtime_error("config: nested --config in a config file is not allowed");
        }

        // F012c: Special case: inline auth_policy is handled separately
        if (key == "auth_policy") {
            if (!value_node.is_mapping()) {
                throw std::runtime_error("config: auth_policy must be a mapping");
            }
            nlohmann::json policy_json = fkyaml_to_json(value_node);
            out_policy_json = policy_json.dump();
            continue;
        }

        // Normalize key: "--" + key with "_" -> "-"
        std::string flag = "--" + normalize_key(key);

        // Look up the flag
        const common_arg * opt = lookup(flag);
        if (!opt) {
            throw std::runtime_error(string_format("config: unknown key '%s' (maps to %s)", key.c_str(), flag.c_str()));
        }

        // Process value based on handler type
        std::string token_value;

        if (value_node.is_null()) {
            throw std::runtime_error(string_format("config: null value for key '%s'", key.c_str()));
        } else if (opt->value_hint == nullptr && opt->value_hint_2 == nullptr) {
            // handler_void or handler_bool: require boolean
            if (!value_node.is_boolean()) {
                throw std::runtime_error(string_format("config: key '%s' requires a boolean value (void/bool flag)", key.c_str()));
            }
            // For handler_bool, preset::to_args will handle negation via is_falsey
            // For handler_void, preset::to_args expects "true" or "false"
            token_value = value_node.get_value<bool>() ? "true" : "false";
        } else if (value_node.is_sequence()) {
            // Sequence -> comma-joined CSV token
            if (value_node.size() == 0) {
                throw std::runtime_error(string_format("config: empty sequence for key '%s'", key.c_str()));
            }
            std::vector<std::string> elements;
            for (size_t i = 0; i < value_node.size(); ++i) {
                const auto & elem = value_node[i];
                if (elem.is_null()) {
                    throw std::runtime_error(string_format("config: null element in sequence for key '%s'", key.c_str()));
                } else if (elem.is_sequence() || elem.is_mapping()) {
                    throw std::runtime_error(string_format("config: nested structure in sequence for key '%s'", key.c_str()));
                }
                elements.push_back(scalar_to_token(elem));
            }
            token_value = "";
            for (size_t i = 0; i < elements.size(); ++i) {
                if (i > 0) token_value += ",";
                token_value += elements[i];
            }
        } else if (value_node.is_mapping()) {
            throw std::runtime_error(string_format("config: nested mapping for key '%s' (scalar or sequence required)", key.c_str()));
        } else {
            // Scalar: string, number, boolean
            token_value = scalar_to_token(value_node);
        }

        preset.options[*opt] = token_value;
    }

    // Use preset::to_args to render (this handles flag/negation semantics)
    return preset.to_args();
}
