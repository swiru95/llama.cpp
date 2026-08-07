#pragma once

#include "server-auth.h"
#include "server-http.h"

// F015: Append auth counter Prometheus text to whatever /metrics produced. Registered at
// the single /metrics call site in server.cpp, wraps both single-server and router-mode handlers.
static server_http_context::handler_t server_metrics_wrap(server_http_context::handler_t inner) {
    return [inner = std::move(inner)](const server_http_req & req) -> server_http_res_ptr {
        auto res = inner(req);

        // Only append if inner succeeded and returned Prometheus text
        if (!res || res->status != 200) {
            return res;
        }
        if (res->content_type.substr(0, 10) != "text/plain") {
            return res;
        }

        // Get auth metrics; return untouched if empty (auth disabled)
        std::string metrics_text = server_auth::metrics_prometheus();
        if (metrics_text.empty()) {
            return res;
        }

        // Append to response
        if (!res->is_stream()) {
            res->data += metrics_text;
            return res;
        }

        // Router mode: wrap the response pump to append on final chunk
        auto inner_next = std::move(res->next);
        res->next = [inner_next = std::move(inner_next), metrics = std::move(metrics_text)](
                      std::string & out) -> bool {
            const bool has_next = inner_next(out);
            if (!has_next) {
                out += metrics;
            }
            return has_next;
        };
        return res;
    };
}
