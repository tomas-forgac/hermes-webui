"""Tests for TLS-aware launcher health probes.

When HERMES_WEBUI_TLS_CERT + HERMES_WEBUI_TLS_KEY are set, server.py serves
https. The launcher health probes (bootstrap.py wait_for_health, start.sh,
ctl.sh status, the WSL autostart) must mirror that scheme and tolerate a
self-signed / untrusted certificate (common for home setups) by retrying the
probe without certificate verification and emitting a warning.
"""
import importlib
import os
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


def _gen_test_cert(tmpdir: Path) -> tuple[str, str]:
    """Generate a self-signed cert and key pair for testing."""
    cert = str(tmpdir / "test_cert.pem")
    key = str(tmpdir / "test_key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", key, "-out", cert, "-days", "1", "-nodes",
         "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


def _find_free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(port: int, cert: str = None, key: str = None) -> subprocess.Popen:
    env = {k: v for k, v in os.environ.items()}
    env["HERMES_WEBUI_HOST"] = "127.0.0.1"
    env["HERMES_WEBUI_PORT"] = str(port)
    env.pop("HERMES_WEBUI_TLS_CERT", None)
    env.pop("HERMES_WEBUI_TLS_KEY", None)
    if cert:
        env["HERMES_WEBUI_TLS_CERT"] = cert
    if key:
        env["HERMES_WEBUI_TLS_KEY"] = key
    env["HERMES_WEBUI_STATE_DIR"] = str(Path(tempfile.mkdtemp()))
    return subprocess.Popen(
        [sys.executable, str(ROOT / "server.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        **({"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}),
    )


def _import_bootstrap():
    if "bootstrap" in sys.modules:
        del sys.modules["bootstrap"]
    return importlib.import_module("bootstrap")


class TestSchemeHelpers(unittest.TestCase):
    """Unit coverage for the pure scheme/insecure helpers (no server needed)."""

    def setUp(self):
        for k in ("HERMES_WEBUI_TLS_CERT", "HERMES_WEBUI_TLS_KEY",
                  "HERMES_WEBUI_TLS_INSECURE_PROBE"):
            os.environ.pop(k, None)
        self.bs = _import_bootstrap()

    def tearDown(self):
        for k in ("HERMES_WEBUI_TLS_CERT", "HERMES_WEBUI_TLS_KEY",
                  "HERMES_WEBUI_TLS_INSECURE_PROBE"):
            os.environ.pop(k, None)

    def test_scheme_http_without_tls(self):
        self.assertFalse(self.bs._tls_enabled())
        self.assertEqual(self.bs._health_scheme(), "http")

    def test_scheme_https_with_both_set(self):
        os.environ["HERMES_WEBUI_TLS_CERT"] = "/tmp/cert.pem"
        os.environ["HERMES_WEBUI_TLS_KEY"] = "/tmp/key.pem"
        self.assertTrue(self.bs._tls_enabled())
        self.assertEqual(self.bs._health_scheme(), "https")

    def test_scheme_http_when_only_cert_set(self):
        os.environ["HERMES_WEBUI_TLS_CERT"] = "/tmp/cert.pem"
        self.assertFalse(self.bs._tls_enabled())
        self.assertEqual(self.bs._health_scheme(), "http")

    def test_insecure_probe_flag_parsing(self):
        for val in ("1", "true", "YES", "on"):
            os.environ["HERMES_WEBUI_TLS_INSECURE_PROBE"] = val
            self.assertTrue(self.bs._insecure_probe_requested(), val)
        for val in ("0", "false", "no", ""):
            os.environ["HERMES_WEBUI_TLS_INSECURE_PROBE"] = val
            self.assertFalse(self.bs._insecure_probe_requested(), val)

    def test_wait_for_health_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            self.bs.wait_for_health("file:///etc/passwd")


class TestWaitForHealthSelfSigned(unittest.TestCase):
    """wait_for_health must succeed against a self-signed https server."""

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._cert, cls._key = _gen_test_cert(cls._tmpdir)

    @classmethod
    def tearDownClass(cls):
        with suppress(Exception):
            import shutil
            shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def setUp(self):
        for k in ("HERMES_WEBUI_TLS_CERT", "HERMES_WEBUI_TLS_KEY",
                  "HERMES_WEBUI_TLS_INSECURE_PROBE"):
            os.environ.pop(k, None)
        self.bs = _import_bootstrap()
        self._proc = None

    def tearDown(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            with suppress(subprocess.TimeoutExpired):
                self._proc.wait(timeout=5)
            if self._proc.poll() is None:
                self._proc.kill()
        for k in ("HERMES_WEBUI_TLS_CERT", "HERMES_WEBUI_TLS_KEY",
                  "HERMES_WEBUI_TLS_INSECURE_PROBE"):
            os.environ.pop(k, None)

    def test_wait_for_health_https_self_signed_falls_back(self):
        port = _find_free_port()
        self._proc = _start_server(port, cert=self._cert, key=self._key)
        url = f"https://127.0.0.1:{port}/health"

        captured = []
        self.bs.warn = lambda msg: captured.append(msg)  # type: ignore[assignment]

        self.assertTrue(
            self.bs.wait_for_health(url, timeout=15.0),
            "wait_for_health should succeed against a self-signed https server",
        )
        self.assertTrue(
            any("certificate" in m.lower() for m in captured),
            f"expected a self-signed cert warning, got: {captured}",
        )

    def test_wait_for_health_http_unaffected(self):
        port = _find_free_port()
        self._proc = _start_server(port)
        url = f"http://127.0.0.1:{port}/health"

        captured = []
        self.bs.warn = lambda msg: captured.append(msg)  # type: ignore[assignment]

        self.assertTrue(self.bs.wait_for_health(url, timeout=15.0))
        self.assertEqual(captured, [], "http probe must not warn about TLS")


class TestCtlStatusHttps(unittest.TestCase):
    """ctl.sh status must probe https and tolerate a self-signed cert."""

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = Path(tempfile.mkdtemp())
        cls._cert, cls._key = _gen_test_cert(cls._tmpdir)

    @classmethod
    def tearDownClass(cls):
        with suppress(Exception):
            import shutil
            shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def setUp(self):
        self._proc = None

    def tearDown(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            with suppress(subprocess.TimeoutExpired):
                self._proc.wait(timeout=5)
            if self._proc.poll() is None:
                self._proc.kill()

    def _wait_https_ready(self, port: int, timeout: float = 15.0) -> bool:
        import http.client
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                c = http.client.HTTPSConnection("127.0.0.1", port, timeout=2, context=ctx)
                c.request("GET", "/health")
                c.getresponse().read()
                c.close()
                return True
            except Exception:
                time.sleep(0.4)
        return False

    def test_health_line_https_self_signed(self):
        if not (ROOT / "ctl.sh").exists():
            self.skipTest("ctl.sh not present")
        port = _find_free_port()
        self._proc = _start_server(port, cert=self._cert, key=self._key)
        self.assertTrue(self._wait_https_ready(port), "https server did not start")

        # Source ctl.sh and call _health_line directly with TLS env set.
        script = (
            f'set -euo pipefail; '
            f'export HERMES_WEBUI_TLS_CERT="{self._cert}"; '
            f'export HERMES_WEBUI_TLS_KEY="{self._key}"; '
            f'HERMES_WEBUI_NO_DOTENV=1 source "{ROOT}/ctl.sh" >/dev/null 2>&1 || true; '
            f'_health_line 127.0.0.1 {port}'
        )
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        out = r.stdout.strip()
        self.assertIn("ok", out, f"expected ok health, got: {out!r} / {r.stderr!r}")
        self.assertIn("not verified", out,
                      f"expected self-signed note, got: {out!r}")


if __name__ == "__main__":
    unittest.main()
