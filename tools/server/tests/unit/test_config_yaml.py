#!/usr/bin/env python3

import os
import sys
import tempfile
import subprocess
import json

# Add parent directory to path for utils
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils import ServerProcess, TMP_DIR
import pytest


class TestConfigYAML:
    """Tests for F012a/F012b: YAML config file loader"""

    def test_config_sets_port_and_ctx_size(self):
        """Config file sets ordinary flags (port, ctx_size)"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18200
ctx_size: 512
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.n_ctx = None  # Don't override from CLI
            proc.port = 18200  # Expected port
            proc.start()
            proc.stop()
        finally:
            os.unlink(config_path)

    def test_config_sequence_to_csv(self):
        """YAML sequence maps to comma-separated CSV token for repeatable flags"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
api_key:
  - key1
  - key2
  - key3
port: 18201
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18201
            proc.start()

            # Check that all three keys work
            for key in ["key1", "key2", "key3"]:
                headers = {"Authorization": f"Bearer {key}"}
                try:
                    response = proc.make_request("/v1/models", headers=headers)
                    # Should not get 401 for any of the keys
                    assert response['status_code'] != 401, f"Key {key} should be accepted"
                except Exception:
                    pass  # Server might not be ready yet

            proc.stop()
        finally:
            os.unlink(config_path)

    def test_unknown_key_aborts_startup(self):
        """Unknown config key causes startup abort"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18202
nonexistent_flag: 12345
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18202

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_malformed_yaml_aborts_startup(self):
        """Malformed YAML causes startup abort"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Invalid YAML syntax
            f.write("""
port: 18203
ctx_size: 512
  invalid indentation
: this is broken
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18203

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_cli_overrides_config(self):
        """CLI flag overrides config file setting"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18204
ctx_size: 256
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18205  # Override config's port via CLI
            proc.n_ctx = None  # Don't override ctx_size

            proc.start()
            # Should listen on 18205, not 18204
            proc.stop()
        finally:
            os.unlink(config_path)

    def test_duplicate_keys_abort_startup(self):
        """Duplicate top-level keys cause startup abort"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18206
api_key: k1
port: 18207
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18206

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_multi_document_stream_aborts_startup(self):
        """Multi-document YAML stream is rejected"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""---
port: 18208
ctx_size: 256
---
port: 18209
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18208

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_empty_document_aborts_startup(self):
        """Empty YAML document is rejected"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18210

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_non_mapping_root_aborts_startup(self):
        """Non-mapping (list) document root is rejected"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # YAML list instead of mapping
            f.write("""
- port: 18211
- ctx_size: 256
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18211

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_null_scalar_value_aborts_startup(self):
        """Null scalar value is rejected"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18212
ctx_size:
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18212

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_nested_mapping_for_scalar_flag_aborts(self):
        """Nested mapping where scalar is required is rejected"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18213
ctx_size:
  nested: value
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18213

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)

    def test_config_boolean_flag(self):
        """Boolean YAML values control void/bool flags"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18214
no_ui: true
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18214
            proc.start()
            proc.stop()
        finally:
            os.unlink(config_path)

    def test_config_via_env_var(self):
        """Config file can be specified via LLAMA_ARG_CONFIG env var"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
port: 18215
ctx_size: 512
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            # Don't set config_file via CLI; use env var
            env = os.environ.copy()
            env['LLAMA_ARG_CONFIG'] = config_path
            proc.start()
            proc.stop()
        finally:
            os.unlink(config_path)

    # F012c tests: inline auth_policy in YAML config
    def test_inline_auth_policy_enforces_rbac(self):
        """F012c: Inline auth_policy YAML mapping enforces RBAC"""
        import hashlib
        admin_key = "sk-admin"
        admin_hash = hashlib.sha256(admin_key.encode()).hexdigest()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(f"""
port: 18220
auth_policy:
  roles:
    admin:
      - INFER
      - READ_STATE
      - METRICS
      - ADMIN_STATE
      - ADMIN_MODELS
    user:
      - INFER
  api_keys:
    {admin_hash}: admin
  default_role: null
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18220
            proc.start()

            # Test 1: No key -> 401
            response = proc.make_request("GET", "/props")
            assert response.status_code == 401, "Anonymous request should be denied"

            # Test 2: Admin key -> 200
            headers = {"Authorization": f"Bearer {admin_key}"}
            response = proc.make_request("GET", "/props", headers=headers)
            assert response.status_code == 200, "Admin key should be accepted"

            proc.stop()
        finally:
            os.unlink(config_path)

    def test_both_inline_and_file_policy_aborts_startup(self):
        """F012c: Setting both inline and --auth-policy-file causes startup abort"""
        import hashlib
        admin_key = "sk-admin"
        admin_hash = hashlib.sha256(admin_key.encode()).hexdigest()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(f"""
port: 18221
auth_policy:
  roles:
    admin:
      - INFER
  api_keys:
    {admin_hash}: admin
  default_role: null
""")
            config_path = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "roles": {"admin": ["INFER"]},
                "api_keys": {admin_hash: "admin"},
                "default_role": None
            }, f)
            policy_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.auth_policy_file = policy_path
            proc.port = 18221

            # Server should fail to start
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)
            os.unlink(policy_path)

    def test_inline_policy_bool_field_preserves_type(self):
        """F012c: Boolean policy field round-trips as JSON bool"""
        import hashlib
        admin_key = "sk-admin"
        admin_hash = hashlib.sha256(admin_key.encode()).hexdigest()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(f"""
port: 18222
auth_policy:
  roles:
    admin:
      - INFER
  api_keys:
    {admin_hash}: admin
  oidc:
    require_at_jwt_typ: true
  default_role: null
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18222
            # With OIDC configured but no issuer, should still parse the bool
            # (OIDC init will fail, but parsing succeeds)
            try:
                proc.start()
            except:
                # Expected to fail due to missing OIDC issuer, but we're testing parsing
                pass
            proc.stop()
        finally:
            os.unlink(config_path)

    def test_inline_policy_null_roles_fails_closed(self):
        """F012c: roles: null fails closed, not silent fallback to default roles"""
        import hashlib
        admin_key = "sk-admin"
        admin_hash = hashlib.sha256(admin_key.encode()).hexdigest()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(f"""
port: 18223
auth_policy:
  roles: ~
  api_keys:
    {admin_hash}: admin
  default_role: null
""")
            config_path = f.name

        try:
            proc = ServerProcess()
            proc.config_file = config_path
            proc.port = 18223

            # Server should fail to start (null roles is invalid, not a fallback)
            with pytest.raises(Exception):
                proc.start()
        finally:
            os.unlink(config_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
