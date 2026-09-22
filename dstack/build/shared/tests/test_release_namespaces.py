# SPDX-FileCopyrightText: © 2026 Alpha Compute
# SPDX-License-Identifier: Apache-2.0

"""Validate registry publish, verification and provenance agree for mixed-case forks."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[4]


class ReleaseNamespaceTests(unittest.TestCase):
    """Execute owner normalization and resolve registry targets without publishing."""

    def test_fork_release_targets_share_owner(self):
        """Catch upstream registry paths that fork credentials cannot publish to."""
        workflows = ROOT / ".github/workflows"
        for component in ("gateway", "kms", "verifier", "local-key-provider"):
            with (
                self.subTest(component=component),
                tempfile.TemporaryDirectory() as tmp,
            ):
                source = (workflows / f"{component}-release.yml").read_text()
                workflow = yaml.safe_load(source)
                steps = workflow["jobs"]["build-and-release"]["steps"]
                normalize = next(
                    s for s in steps if s.get("name") == "Normalise registry owner"
                )
                env_file = Path(tmp) / "env"
                # Actions uses GNU Bash; macOS's bundled Bash predates lowercase expansion.
                bash = shutil.which("bash")
                subprocess.run(
                    [bash, "-e", "-c", normalize["run"]],
                    env={
                        **os.environ,
                        "GITHUB_REPOSITORY_OWNER": "AlphaCompute",
                        "GITHUB_ENV": str(env_file),
                    },
                    check=True,
                )
                owner = dict(
                    line.split("=", 1) for line in env_file.read_text().splitlines()
                )["OWNER_LC"]
                self.assertEqual(owner, "alphacompute")
                rendered = source.replace("${{ env.OWNER_LC }}", owner).replace(
                    "${OWNER_LC}", owner
                )
                image = (
                    "local-key-provider"
                    if component == "local-key-provider"
                    else f"dstack-{component}"
                )
                target = f"ghcr.io/{owner}/{image}"
                # These are separate external protocol surfaces, all of which must
                # identify the artifact published by this repository's token.
                parsed = yaml.safe_load(rendered)
                resolved_steps = parsed["jobs"]["build-and-release"]["steps"]
                provenance = next(
                    s
                    for s in resolved_steps
                    if s.get("name") == "Generate artifact attestation"
                )
                self.assertEqual(provenance["with"]["subject-name"], target)
                pull = next(
                    s
                    for s in resolved_steps
                    if s.get("name") == "Verify anonymous pull access"
                )["run"]
                self.assertIn(f"repository:{owner}/{image}:pull", pull)
                self.assertIn(f"ghcr.io/v2/{owner}/{image}/manifests/", pull)
                self.assertNotIn("ghcr.io/dstack-tee/", rendered)
                self.assertNotIn("repository:dstack-tee/", rendered)
                publish = next(
                    s
                    for s in resolved_steps
                    if "IMAGE_NAME" in s.get("env", {}) or "tags" in s.get("with", {})
                )
                published = publish.get("env", {}).get(
                    "IMAGE_NAME", publish.get("with", {}).get("tags")
                )
                self.assertTrue(published.startswith(target + ":"), published)
