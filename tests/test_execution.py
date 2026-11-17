"""The command executor: sanitising, output shaping, capture, timeout rules and the docker argv.

The pure helpers are tested directly. `DockerExecutor.run` is tested with a fake popen, so no
container is started. Sample text is neutral: plain words, a placeholder flag and repeated letters.
"""

import io
import subprocess

import pytest

import execution
from execution import (
    SEND_CAP, SEND_HEAD, SEND_TAIL, STORE_CAP, TAIL_KEEP, DockerExecutor, ExecResult, StreamCapture,
    classify_timeout, sanitize, shape_output,
)

MARKER = "<MARK>"
NOTICE = "<TIMEOUT>"
FLAG = "FLAG-sample-0000000000000000"


def shaped(data: bytes, timed_out: bool = False):
    """shape_output for data that fits the store: the tail is the same bytes."""
    return shape_output(data, data[-TAIL_KEEP:], len(data), timed_out=timed_out, marker=MARKER, notice=NOTICE)


# --- sanitize ----------------------------------------------------------------

def test_sanitize_strips_a_csi_colour_code():
    assert sanitize("\x1b[31mred\x1b[0m") == "red"


def test_sanitize_strips_an_osc_title():
    assert sanitize("\x1b]0;title\x07x") == "x"


def test_sanitize_keeps_tab_and_newline():
    assert sanitize("a\tb\nc") == "a\tb\nc"


@pytest.mark.parametrize("char", ["\r", "\x00", "\x7f", "\x85"])
def test_sanitize_removes_control_characters(char):
    assert sanitize(f"a{char}b") == "ab"


def test_sanitize_leaves_ordinary_non_ascii_text_alone():
    assert sanitize("café 😀") == "café 😀"


# --- shape_output ------------------------------------------------------------

def test_small_output_is_unchanged():
    assert shape_output(b"hello\n", b"hello\n", 6, timed_out=False, marker=MARKER, notice=NOTICE) == \
        ("hello\n", "hello\n", False)


def test_exactly_send_cap_bytes_is_not_truncated():
    assert shaped(b"a" * SEND_CAP) == ("a" * SEND_CAP, "a" * SEND_CAP, False)


def test_one_byte_over_send_cap_is_truncated():
    assert shaped(b"a" * (SEND_CAP + 1))[2] is True


def test_truncated_output_is_head_marker_tail():
    data = b"A" * SEND_HEAD + b"M" * 1000 + b"Z" * SEND_TAIL
    _, sent, truncated = shaped(data)
    assert truncated is True
    assert sent == "A" * SEND_HEAD + "\n" + MARKER + "\n" + "Z" * SEND_TAIL


def test_flag_at_the_start_and_end_of_a_long_output_is_shown():
    body = b"." * (100 * 1024 - len(FLAG))
    _, at_start, _ = shaped(FLAG.encode() + body)
    _, at_end, _ = shaped(body + FLAG.encode())
    assert FLAG in at_start
    assert FLAG in at_end


def test_flag_in_the_middle_of_a_long_output_is_not_shown():
    half = 50 * 1024
    _, sent, _ = shaped(b"." * half + FLAG.encode() + b"." * half)
    assert FLAG not in sent


def test_output_over_store_cap_shows_the_true_end_of_the_stream():
    head = b"H" * STORE_CAP
    tail = b"T" * TAIL_KEEP  # the stream's real last bytes; the head is not the end
    output_full, sent, truncated = shape_output(head, tail, 3 * STORE_CAP, timed_out=False,
                                                marker=MARKER, notice=NOTICE)
    assert truncated is True
    assert len(output_full) == STORE_CAP
    assert sent == "H" * SEND_HEAD + "\n" + MARKER + "\n" + "T" * SEND_TAIL


def test_timeout_notice_follows_the_output_on_its_own_line():
    assert shaped(b"hello\n", timed_out=True)[1] == f"hello\n\n{NOTICE}"


def test_timeout_with_no_output_is_the_notice_alone():
    assert shaped(b"", timed_out=True)[1] == NOTICE


def test_timeout_notice_comes_after_the_tail_of_truncated_output():
    data = b"a" * (SEND_CAP + 1)
    _, sent, _ = shaped(data, timed_out=True)
    assert sent.endswith("\n" + NOTICE)
    assert sent.split("\n" + MARKER + "\n")[1] == "a" * SEND_TAIL + "\n" + NOTICE


def test_invalid_utf8_becomes_replacement_characters():
    output_full, _, _ = shaped(b"\xff\xfe")
    assert output_full == "��"


def test_ansi_escapes_are_stored_but_not_sent():
    data = b"\x1b[31mred\x1b[0m"
    output_full, sent, _ = shaped(data)
    assert output_full == "\x1b[31mred\x1b[0m"
    assert sent == "red"


def test_cutting_never_splits_a_character():
    _, sent, _ = shaped(("é" * 5000).encode("utf-8"))
    head_part, tail_part = sent.split("\n" + MARKER + "\n")
    assert "�" not in head_part
    assert "�" not in tail_part


# --- StreamCapture -----------------------------------------------------------

def test_capture_keeps_head_up_to_the_cap_and_a_rolling_tail():
    capture = StreamCapture(store_cap=10, tail_keep=4)
    capture.feed(b"0123456")
    capture.feed(b"789ABCDEF")
    assert capture.snapshot() == (b"0123456789", b"CDEF", 16)


def test_capture_keeps_a_small_feed_entirely_in_head():
    capture = StreamCapture(store_cap=10, tail_keep=4)
    capture.feed(b"abc")
    assert capture.snapshot() == (b"abc", b"abc", 3)


def test_pump_reads_to_eof_like_feeding_the_same_bytes():
    data = b"x" * 70000 + b"END"
    pumped = StreamCapture()
    pumped.pump(io.BufferedReader(io.BytesIO(data)))
    fed = StreamCapture()
    fed.feed(data)
    assert pumped.snapshot() == fed.snapshot()
    assert pumped.snapshot()[2] == len(data)


# --- classify_timeout --------------------------------------------------------

def test_hard_deadline_is_always_a_timeout():
    assert classify_timeout(0, 0.0, 30, hard_deadline=True) is True


@pytest.mark.parametrize("code", [124, 137])
@pytest.mark.parametrize("elapsed", [29.5, 30.0])
def test_timeout_exit_codes_count_when_the_command_ran_the_full_limit(code, elapsed):
    assert classify_timeout(code, elapsed, 30, hard_deadline=False) is True


def test_exit_124_from_a_command_that_exits_early_is_not_a_timeout():
    assert classify_timeout(124, 1.0, 30, hard_deadline=False) is False


def test_ordinary_exit_after_a_long_run_is_not_a_timeout():
    assert classify_timeout(0, 100.0, 30, hard_deadline=False) is False


def test_no_exit_code_without_a_hard_deadline_is_not_a_timeout():
    assert classify_timeout(None, 100.0, 30, hard_deadline=False) is False


# --- DockerExecutor: argv ----------------------------------------------------

def make_executor(popen=None):
    return DockerExecutor("lab-x-attacker-1", marker=MARKER, notice=NOTICE, popen=popen)


def test_argv_is_the_fixed_docker_exec_prefix_and_the_command():
    assert make_executor().argv("ls") == [
        "docker", "exec", "--user", "agent", "--workdir", "/home/agent",
        "--env", "HOME=/home/agent", "--env", "TERM=dumb",
        "lab-x-attacker-1",
        "timeout", "-s", "KILL", "30", "bash", "-lc", "--", "ls",
    ]


def test_a_command_full_of_metacharacters_stays_one_argument():
    command = "echo a; echo $HOME | cat `x`"
    argv = make_executor().argv(command)
    assert argv[-1] == command
    assert argv[-4:] == ["bash", "-lc", "--", command]


def test_argv_never_uses_docker_compose():
    assert not any("compose" in part for part in make_executor().argv("ls"))


# --- DockerExecutor: run -----------------------------------------------------

class FakeProc:
    """Stands in for subprocess.Popen: a stdout pipe, a wait that returns or times out, and kill()."""

    def __init__(self, output: bytes = b"", code: int = 0, timeout_first: bool = False):
        self.stdout = io.BufferedReader(io.BytesIO(output))
        self.code, self.timeout_first = code, timeout_first
        self.waits = 0
        self.killed = False

    def wait(self, timeout=None):
        self.waits += 1
        if self.timeout_first and self.waits == 1:
            raise subprocess.TimeoutExpired(cmd="docker exec", timeout=timeout)
        return -9 if self.timeout_first else self.code

    def kill(self):
        self.killed = True


class FakePopen:
    """Records the call and returns one FakeProc."""

    def __init__(self, proc: FakeProc):
        self.proc = proc
        self.args = None
        self.kwargs = None

    def __call__(self, args, **kwargs):
        self.args, self.kwargs = args, kwargs
        return self.proc


def test_run_returns_normal_output_and_passes_the_safe_popen_options():
    popen = FakePopen(FakeProc(b"hello\n", code=0))
    result = make_executor(popen).run("echo hello")
    assert result == ExecResult(output_full="hello\n", output_sent="hello\n", truncated=False,
                                exit_code=0, timed_out=False)
    assert popen.kwargs["stdin"] is subprocess.DEVNULL
    assert popen.kwargs["stdout"] is subprocess.PIPE
    assert popen.kwargs["stderr"] is subprocess.STDOUT
    assert popen.kwargs["shell"] is False


def test_run_treats_exit_137_at_the_time_limit_as_a_timeout(monkeypatch):
    readings = iter([0.0])
    monkeypatch.setattr(execution.time, "monotonic", lambda: next(readings, 31.0))
    result = make_executor(FakePopen(FakeProc(b"partial\n", code=137))).run("sleep 99")
    assert result.timed_out is True
    assert result.exit_code == 137
    assert result.output_sent.endswith(NOTICE)


def test_run_kills_the_client_when_the_hard_deadline_passes():
    proc = FakeProc(b"", timeout_first=True)
    result = make_executor(FakePopen(proc)).run("sleep 99")
    assert proc.killed is True
    assert result.timed_out is True
    assert result.exit_code is None


def test_run_reports_a_nonzero_exit_that_is_not_a_timeout():
    result = make_executor(FakePopen(FakeProc(b"boom", code=1))).run("false")
    assert result == ExecResult(output_full="boom", output_sent="boom", truncated=False,
                                exit_code=1, timed_out=False)


def test_a_command_that_starts_with_a_dash_is_still_a_command_string():
    # Without "--", `bash -lc -x` fails with "option requires an argument": bash reads the command as an option.
    argv = DockerExecutor("lab-x-attacker-1", marker="m", notice="n").argv("-x")
    assert argv[-4:] == ["bash", "-lc", "--", "-x"]
