# This file is part of cloud-init. See LICENSE file for license information.

from pathlib import Path

ROOT = Path(__file__).parents[3]


def test_pocketforge_binary_package_has_minimal_dependencies():
    control = (ROOT / "packages/debian/control.in").read_text()
    stanza = control.split("Package: cloud-init-pocketforge\n", 1)[1].split(
        "\n\n", 1
    )[0]
    dependencies = stanza.split("Depends: ", 1)[1].split("\nConflicts:", 1)[0]

    assert "Architecture: all" in stanza
    assert "Build-Profiles: <pkg.pocketforge>" in stanza
    assert "python3" in dependencies
    for excluded in (
        "cloud-guest-utils",
        "dhcpcd",
        "netcat",
        "netplan",
        "python3-oauthlib",
        "python3-passlib",
        "python3-serial",
    ):
        assert excluded not in dependencies


def test_pocketforge_profile_installs_into_its_binary_package():
    rules = (ROOT / "packages/debian/rules").read_text()

    assert "PACKAGE_DEST = cloud-init-base" in rules
    assert "PACKAGE_DEST = cloud-init-pocketforge" in rules
    assert "--destdir=debian/$(PACKAGE_DEST)" in rules


def test_bddeb_preserves_pocketforge_build_inputs():
    bddeb = (ROOT / "packages/bddeb").read_text()

    assert '"POCKETFORGE_BUILD"' in bddeb
    assert '"SOURCE_DATE_EPOCH"' in bddeb
    assert '"DEB_BUILD_PROFILES"' in bddeb
    assert '"pkg.pocketforge"' in bddeb
