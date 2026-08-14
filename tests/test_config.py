"""Configuration loading, merging, coercion and validation."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from flowlite import _miniyaml
from flowlite.config import DEFAULTS, Config, default_config, load_config
from flowlite.errors import ConfigError


def write(tmp_path: Path, text: str, name: str = "flowlite.yaml") -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


class TestDefaults:
    def test_every_key_exists_without_a_file(self):
        cfg = default_config()
        assert cfg.capture.source == "folder"
        assert cfg.analytics.flow.idle_timeout_s == 60
        assert cfg.logging.level == "INFO"

    def test_missing_file_is_not_fatal(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FLOWLITE_CONFIG", raising=False)
        cfg = load_config(allow_missing=True)
        assert isinstance(cfg, Config)
        assert any("No configuration file" in w for w in cfg.warnings)

    def test_missing_file_can_be_fatal_on_request(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("FLOWLITE_CONFIG", raising=False)
        with pytest.raises(ConfigError, match="No configuration file"):
            load_config(allow_missing=False)

    def test_unknown_key_raises_a_clear_error_not_attributeerror(self):
        cfg = default_config()
        with pytest.raises(ConfigError, match="No such configuration key"):
            _ = cfg.capture.does_not_exist

    def test_partial_file_keeps_every_other_default(self, tmp_path):
        path = write(tmp_path, "capture:\n  rotate_seconds: 120\n")
        cfg = load_config(path)
        assert cfg.capture.rotate_seconds == 120
        assert (
            cfg.capture.folder.poll_interval_s == DEFAULTS["capture"]["folder"]["poll_interval_s"]
        )
        assert cfg.analytics.network_ts.bucket_seconds == 60


class TestCoercion:
    def test_numeric_strings_are_accepted(self, tmp_path):
        path = write(tmp_path, 'capture:\n  rotate_seconds: "600"\n  ssh:\n    port: "2222"\n')
        cfg = load_config(path)
        assert cfg.capture.rotate_seconds == 600
        assert cfg.capture.ssh.port == 2222

    def test_boolean_strings_are_accepted(self, tmp_path):
        path = write(tmp_path, 'telemetry:\n  enabled: "no"\n')
        assert load_config(path).telemetry.enabled is False

    def test_comma_separated_string_becomes_a_list(self, tmp_path):
        path = write(tmp_path, 'capture:\n  folder:\n    patterns: "*.pcap, *.cap"\n')
        assert load_config(path).capture.folder.patterns == ["*.pcap", "*.cap"]

    def test_bad_type_is_reported_not_crashed(self, tmp_path):
        path = write(tmp_path, "capture:\n  rotate_seconds: not-a-number\n")
        with pytest.raises(ConfigError, match="expected an integer"):
            load_config(path)

    def test_explicit_null_keeps_the_default(self, tmp_path):
        path = write(tmp_path, "capture:\n  rotate_seconds:\n")
        assert load_config(path).capture.rotate_seconds == 3600


class TestValidation:
    def test_every_problem_is_reported_at_once(self, tmp_path):
        path = write(
            tmp_path,
            "capture:\n  source: banana\ntelemetry:\n  driver: snmp\n  interval_s: 1\n",
        )
        with pytest.raises(ConfigError) as excinfo:
            load_config(path)
        assert len(excinfo.value.problems) >= 3
        text = str(excinfo.value)
        assert "banana" in text and "minimum" in text

    def test_enum_case_is_normalised(self, tmp_path):
        path = write(tmp_path, "logging:\n  level: debug\n")
        assert load_config(path).logging.level == "DEBUG"

    def test_ssh_capture_requires_a_host(self, tmp_path):
        path = write(tmp_path, "capture:\n  source: ssh\n")
        with pytest.raises(ConfigError, match="capture.ssh.host"):
            load_config(path)

    def test_colliding_collector_ports_are_rejected(self, tmp_path):
        path = write(
            tmp_path,
            "flowproto:\n  enabled: true\n  sflow:\n    enabled: true\n    port: 9995\n"
            "  netflow:\n    enabled: true\n    port: 9995\n",
        )
        with pytest.raises(ConfigError, match="same address and port"):
            load_config(path)

    def test_unknown_keys_warn_by_default_and_fail_under_strict(self, tmp_path):
        path = write(tmp_path, "captrue:\n  source: folder\n")
        cfg = load_config(path)
        assert any("captrue" in w for w in cfg.warnings)
        with pytest.raises(ConfigError, match="captrue"):
            load_config(path, strict_unknown=True)

    def test_insecure_host_key_policy_warns(self, tmp_path):
        path = write(
            tmp_path,
            "device:\n  host: 10.0.0.1\ncapture:\n  source: ssh\n"
            "  ssh:\n    host_key_policy: ignore\n",
        )
        cfg = load_config(path)
        assert any("host key" in w.lower() for w in cfg.warnings)


class TestEnvironmentAndOverrides:
    def test_environment_substitution(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FL_TEST_COMMUNITY", "s3cret")
        path = write(tmp_path, "credentials:\n  snmp_community: ${FL_TEST_COMMUNITY}\n")
        assert load_config(path).credentials.snmp_community == "s3cret"

    def test_environment_fallback(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FL_ABSENT", raising=False)
        path = write(tmp_path, "instance: ${FL_ABSENT:-fallback-name}\n")
        assert load_config(path).instance == "fallback-name"

    def test_unset_variable_without_fallback_is_an_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FL_ABSENT", raising=False)
        path = write(tmp_path, "instance: ${FL_ABSENT}\n")
        with pytest.raises(ConfigError, match="FL_ABSENT"):
            load_config(path)

    def test_cli_overrides(self, tmp_path):
        path = write(tmp_path, "instance: base\n")
        cfg = load_config(path, overrides=["instance=overridden", "telemetry.interval_s=45"])
        assert cfg.instance == "overridden"
        assert cfg.telemetry.interval_s == 45

    def test_secrets_are_redacted(self, tmp_path):
        path = write(tmp_path, "credentials:\n  password: hunter2\n  snmp_community: private\n")
        cfg = load_config(path)
        redacted = cfg.redacted()
        assert redacted["credentials"]["password"] == "***redacted***"
        assert redacted["credentials"]["snmp_community"] == "***redacted***"
        assert "hunter2" not in json.dumps(redacted)


class TestPathsAndInheritance:
    def test_paths_derive_from_data_dir(self, tmp_path):
        path = write(tmp_path, f"paths:\n  data_dir: {json.dumps(str(tmp_path / 'root'))}\n")
        cfg = load_config(path)
        root = tmp_path / "root"
        assert Path(cfg.paths.flows_dir) == root / "flows"
        assert Path(cfg.paths.network_ts) == root / "network_ts.csv"
        assert Path(cfg.capture.folder.watch_dir) == root / "incoming"

    def test_explicit_paths_win(self, tmp_path):
        custom = tmp_path / "elsewhere" / "flows"
        path = write(tmp_path, f"paths:\n  flows_dir: {json.dumps(str(custom))}\n")
        assert Path(load_config(path).paths.flows_dir) == custom

    def test_drivers_inherit_device_host_and_credentials(self, tmp_path):
        path = write(
            tmp_path,
            "device:\n  host: 10.1.1.1\ncredentials:\n  username: u\n  password: p\n"
            "  snmp_community: c\ncapture:\n  source: ssh\ntelemetry:\n  driver: snmp\n",
        )
        cfg = load_config(path)
        assert cfg.capture.ssh.host == "10.1.1.1"
        assert cfg.capture.ssh.username == "u"
        assert cfg.telemetry.snmp.host == "10.1.1.1"
        assert cfg.telemetry.snmp.community == "c"

    def test_device_name_defaults_to_host(self, tmp_path):
        path = write(tmp_path, "device:\n  host: 10.2.2.2\n")
        assert load_config(path).device.name == "10.2.2.2"


class TestJsonAndYamlSources:
    def test_json_config(self, tmp_path):
        path = tmp_path / "flowlite.json"
        path.write_text(json.dumps({"instance": "from-json"}), encoding="utf-8")
        assert load_config(str(path)).instance == "from-json"

    def test_flowlite_wrapper_key_is_unwrapped(self, tmp_path):
        path = write(tmp_path, "flowlite:\n  instance: wrapped\n")
        assert load_config(path).instance == "wrapped"

    def test_env_var_selects_the_config(self, tmp_path, monkeypatch):
        path = write(tmp_path, "instance: via-env\n", name="custom.yaml")
        monkeypatch.setenv("FLOWLITE_CONFIG", path)
        assert load_config().instance == "via-env"

    def test_missing_explicit_file_is_an_error(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(str(tmp_path / "nope.yaml"))


class TestMiniYaml:
    """The fallback parser must agree with PyYAML on FlowLite's own files."""

    @pytest.mark.parametrize(
        "source",
        [
            "a: 1\nb: two\nc: true\n",
            "outer:\n  inner:\n    value: 3.5\n    flag: false\n",
            "items:\n  - one\n  - two\n  - 3\n",
            "inline: [1, 2, 3]\nmap: {a: 1, b: two}\n",
            "quoted: 'has: colon'\ndouble: \"tab\\there\"\n",
            "empty:\nnothing: ~\n",
            "commands:\n  - name: a\n    command: show one\n  - name: b\n    command: show two\n",
            "# leading comment\nkey: value  # trailing comment\n",
            "---\ndoc: started\n",
        ],
    )
    def test_matches_pyyaml(self, source):
        yaml = pytest.importorskip("yaml")
        assert _miniyaml.safe_load(source) == yaml.safe_load(source)

    def test_parses_the_shipped_example(self):
        yaml = pytest.importorskip("yaml")
        example = Path(__file__).resolve().parent.parent / "configs" / "flowlite.example.yaml"
        source = example.read_text(encoding="utf-8")
        assert _miniyaml.safe_load(source) == yaml.safe_load(source)

    def test_tabs_are_rejected_loudly(self):
        with pytest.raises(ConfigError, match="tab"):
            _miniyaml.safe_load("a:\n\tb: 1\n")

    def test_anchors_are_rejected_rather_than_misread(self):
        with pytest.raises(ConfigError):
            _miniyaml.safe_load("base: &anchor\n  a: 1\nother: *anchor\n")

    def test_used_when_pyyaml_is_absent(self, tmp_path, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("simulated absence")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        path = write(tmp_path, "instance: no-pyyaml\ncapture:\n  rotate_seconds: 300\n")
        cfg = load_config(path)
        assert cfg.instance == "no-pyyaml"
        assert cfg.capture.rotate_seconds == 300


class TestShippedProfiles:
    """Every profile in configs/profiles/ must load without error."""

    @pytest.mark.parametrize(
        "profile",
        sorted(
            p.name
            for p in (Path(__file__).resolve().parent.parent / "configs" / "profiles").glob(
                "*.yaml"
            )
        ),
    )
    def test_profile_loads(self, profile, monkeypatch):
        monkeypatch.setenv("FLOWLITE_USER", "u")
        monkeypatch.setenv("FLOWLITE_PASS", "p")
        monkeypatch.setenv("FLOWLITE_SNMP", "c")
        root = Path(__file__).resolve().parent.parent / "configs" / "profiles"
        cfg = load_config(str(root / profile), strict_unknown=True)
        assert cfg.instance
        assert cfg.capture.source in ("folder", "ssh", "local", "none")

    def test_example_config_loads_strictly(self):
        example = Path(__file__).resolve().parent.parent / "configs" / "flowlite.example.yaml"
        cfg = load_config(str(example), strict_unknown=True)
        assert cfg.capture.source == "folder"
        assert not [w for w in cfg.warnings if "unknown configuration key" in w]

    def test_example_config_covers_every_default_key(self):
        """A key that exists in code but not in the example is undiscoverable."""
        example = Path(__file__).resolve().parent.parent / "configs" / "flowlite.example.yaml"
        text = example.read_text(encoding="utf-8")

        def leaves(node, prefix=""):
            for key, value in node.items():
                if isinstance(value, dict):
                    yield from leaves(value, f"{prefix}{key}.")
                else:
                    yield f"{prefix}{key}"

        missing = [name for name in leaves(DEFAULTS) if name.split(".")[-1] not in text]
        assert not missing, f"undocumented configuration keys: {missing}"


def test_config_survives_a_hostile_file(tmp_path):
    """Garbage in must produce a clear error, never a traceback from deep code."""
    for content in ("[]\n", "just a string\n", "1234\n"):
        path = write(tmp_path, content, name="hostile.yaml")
        with pytest.raises(ConfigError):
            load_config(path)


def test_environment_config_pointing_at_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("FLOWLITE_CONFIG", str(tmp_path / "absent.yaml"))
    with pytest.raises(ConfigError, match="FLOWLITE_CONFIG"):
        load_config()
    os.environ.pop("FLOWLITE_CONFIG", None)
