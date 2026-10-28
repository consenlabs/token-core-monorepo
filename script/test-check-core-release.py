#!/usr/bin/env python3
"""Regression tests for repeated publication and failed preflight checks."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

spec = importlib.util.spec_from_file_location("release_check", Path(__file__).with_name("check-core-release.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
VERSION = "2.8.4+5642d8a"
COMMIT = "5642d8ae3857655616687a632569fd51f05f23ca"
RELEASE = {
    "tag_name": f"v{VERSION}", "draft": False, "immutable": True,
    "assets": [{"name": f"ios-{kind}-{VERSION}.zip", "state": "uploaded", "size": 100}
               for kind in ("ikc", "tcx")],
}


def json_response(value):
    return {}, json.dumps(value).encode()


class PublicationTests(unittest.TestCase):
    def ios(self):
        return check.ios_published(VERSION, "consenlabs/token-core-monorepo", COMMIT, "test-token")

    def test_new_ios_release(self):
        with patch.object(check, "request", return_value=None):
            self.assertFalse(self.ios())

    def test_complete_immutable_ios_release(self):
        with patch.object(check, "request", side_effect=[json_response(RELEASE), json_response({"sha": COMMIT})]) as request:
            self.assertTrue(self.ios())
            self.assertIn("v2.8.4%2B5642d8a", request.call_args_list[0].args[0])

    def test_incomplete_ios_release(self):
        for change in ("missing", "empty", "uploading", "draft"):
            release = copy.deepcopy(RELEASE)
            if change == "missing":
                release["assets"].pop()
            elif change == "empty":
                release["assets"][0]["size"] = 0
            elif change == "uploading":
                release["assets"][0]["state"] = "new"
            else:
                release["draft"] = True
            with self.subTest(change=change), patch.object(check, "request", side_effect=[json_response(release), json_response({"sha": COMMIT})]):
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    self.ios()

    def test_ios_tag_commit_mismatch(self):
        with patch.object(check, "request", side_effect=[json_response(RELEASE), json_response({"sha": "another-commit"})]):
            with self.assertRaisesRegex(ValueError, "different commit"):
                self.ios()

    def test_new_android_version(self):
        with patch.object(check, "request", return_value=None) as request:
            self.assertFalse(check.android_published(VERSION))
            self.assertEqual(request.call_count, 12)

    def test_complete_android_version(self):
        with patch.object(check, "request", return_value=({"Content-Length": "100"}, b"")) as request:
            self.assertTrue(check.android_published(VERSION))
            self.assertEqual(request.call_count, 12)
            self.assertTrue(all(call.kwargs["method"] == "HEAD" for call in request.call_args_list))
            self.assertIn("2.8.4%2B5642d8a", request.call_args.args[0])

    def test_partial_android_version(self):
        with patch.object(check, "request", side_effect=[({"Content-Length": "100"}, b"")] + [None] * 11):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                check.android_published(VERSION)

    def test_empty_android_artifact(self):
        with patch.object(check, "request", return_value=({"Content-Length": "0"}, b"")):
            with self.assertRaisesRegex(ValueError, "empty"):
                check.android_published(VERSION)

    def test_only_404_means_missing(self):
        for code in (401, 403, 429, 500, 503):
            with self.subTest(code=code), patch.object(check, "urlopen", side_effect=HTTPError("https://example.test", code, "failure", {}, None)):
                with self.assertRaises(HTTPError):
                    check.request("https://example.test")
        with patch.object(check, "urlopen", side_effect=HTTPError("https://example.test", 404, "missing", {}, None)):
            self.assertIsNone(check.request("https://example.test"))

    def test_output_is_written_only_after_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.dict(os.environ, {"RELEASE_VERSION": VERSION, "GITHUB_OUTPUT": str(output)}), patch.object(check.sys, "argv", ["check", "android"]):
                with patch.object(check, "request", side_effect=URLError("network unavailable")):
                    with self.assertRaises(URLError):
                        check.main()
                    self.assertFalse(output.exists())
                with patch.object(check, "request", return_value=None):
                    check.main()
                    self.assertEqual(output.read_text(), "published=false\n")
                with patch.object(check, "request", return_value=({"Content-Length": "100"}, b"")):
                    check.main()
                    self.assertEqual(output.read_text(), "published=false\npublished=true\n")


if __name__ == "__main__":
    unittest.main()
