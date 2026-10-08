# This file is part of cloud-init. See LICENSE file for license information.

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from cloudinit import pocketforge

VALID_USER_DATA = """\
#cloud-config
hostname: pocketforge-bench
ssh_pwauth: false
disable_root: true
users:
  - name: gamer
    lock_passwd: true
    ssh_authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest bench@example
"""

VALID_NETWORK_CONFIG = """\
version: 2
wifis:
  wlan0:
    dhcp4: true
    regulatory-domain: GB
    access-points:
      Bench Network:
        password: correct horse battery staple
"""


def _write_seed(root: Path, *, user_data=VALID_USER_DATA, network=None):
    (root / "user-data").write_text(user_data, encoding="utf-8")
    (root / "network-config").write_text(
        network or VALID_NETWORK_CONFIG, encoding="utf-8"
    )
    (root / "meta-data").write_text(
        "instance-id: bench-001\n", encoding="utf-8"
    )


def test_seed_aliases_normalize_bom_crlf_and_ignore_appledouble(tmp_path):
    (tmp_path / "user-data.txt").write_bytes(
        b"\xef\xbb\xbf" + VALID_USER_DATA.replace("\n", "\r\n").encode()
    )
    (tmp_path / "network-config.yaml").write_text(VALID_NETWORK_CONFIG)
    (tmp_path / "._user-data.txt").write_bytes(b"not a second seed")

    seed = pocketforge.load_seed(tmp_path)

    assert seed.user_data.startswith("#cloud-config\n")
    assert "\r" not in seed.user_data
    assert seed.paths["user-data"].name == "user-data.txt"
    assert seed.paths["network-config"].name == "network-config.yaml"
    assert seed.metadata["instance-id"].startswith("pf-")
    assert len(seed.metadata["instance-id"]) == len("pf-") + 16


def test_generated_instance_id_does_not_derive_from_wifi_secret(tmp_path):
    _write_seed(tmp_path)
    (tmp_path / "meta-data").unlink()
    first = pocketforge.load_seed(tmp_path).metadata["instance-id"]

    changed_secret = VALID_NETWORK_CONFIG.replace(
        "correct horse battery staple", "another acceptable passphrase"
    )
    (tmp_path / "network-config").write_text(changed_secret, encoding="utf-8")
    second = pocketforge.load_seed(tmp_path).metadata["instance-id"]

    assert first == second


def test_duplicate_alias_is_refused_without_mutating_seed(tmp_path):
    _write_seed(tmp_path)
    duplicate = tmp_path / "user-data.yaml"
    duplicate.write_text(VALID_USER_DATA)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    with pytest.raises(pocketforge.SeedRefused) as exc:
        pocketforge.load_seed(tmp_path)

    assert "duplicate variants" in str(exc.value)
    assert before == {
        path.name: path.read_bytes() for path in tmp_path.iterdir()
    }


@pytest.mark.parametrize(
    "user_data,needle",
    [
        (
            VALID_USER_DATA.replace("ssh_pwauth: false", "ssh_pwauth: true"),
            "ssh_pwauth",
        ),
        (
            VALID_USER_DATA + "unknown-dangerous-key: true\n",
            "unknown-dangerous-key",
        ),
        (
            VALID_USER_DATA
            + "write_files:\n"
            + "  - path: /etc/pocketforge/test\n"
            + "    content: safe\n"
            + "    surprise: refused\n",
            "surprise",
        ),
        ("#include\nhttps://metadata.invalid/config\n", "#include"),
    ],
)
def test_policy_refuses_whole_seed_with_file_and_line(
    tmp_path, user_data, needle
):
    _write_seed(tmp_path, user_data=user_data)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    with pytest.raises(pocketforge.SeedRefused) as exc:
        pocketforge.load_seed(tmp_path)

    assert needle in str(exc.value)
    assert "user-data:" in str(exc.value)
    assert before == {
        path.name: path.read_bytes() for path in tmp_path.iterdir()
    }


@pytest.mark.parametrize(
    "network,needle",
    [
        ("version: 1\nconfig: []\n", "version 2"),
        (
            VALID_NETWORK_CONFIG.replace("wlan0:", "wlan1:"),
            "only wlan0",
        ),
        (VALID_NETWORK_CONFIG + "renderer: NetworkManager\n", "renderer"),
        (
            VALID_NETWORK_CONFIG.replace(
                "password: correct horse battery staple",
                "auth:\n          key-management: eap",
            ),
            "auth",
        ),
    ],
)
def test_network_policy_refuses_unsupported_inputs(tmp_path, network, needle):
    _write_seed(tmp_path, network=network)

    with pytest.raises(pocketforge.SeedRefused) as exc:
        pocketforge.load_seed(tmp_path)

    assert needle in str(exc.value)
    assert "network-config:" in str(exc.value)


def test_password_b64_is_decoded_strictly_and_derived_to_pmk(tmp_path):
    password = b"correct horse battery staple"
    network = VALID_NETWORK_CONFIG.replace(
        "password: correct horse battery staple",
        "password-b64: " + base64.b64encode(password).decode(),
    )
    _write_seed(tmp_path, network=network)

    seed = pocketforge.load_seed(tmp_path)
    credentials = pocketforge.derive_wifi_credentials(seed.network_config)

    expected = hashlib.pbkdf2_hmac(
        "sha1", password, b"Bench Network", 4096, 32
    ).hex()
    assert credentials == {"net00": expected}
    assert password.decode() not in repr(seed)
    assert password.decode() not in repr(credentials)


def test_password_b64_refuses_non_printable_passphrase(tmp_path):
    network = VALID_NETWORK_CONFIG.replace(
        "password: correct horse battery staple",
        "password-b64: " + base64.b64encode(b"eightbyt\x00").decode(),
    )
    _write_seed(tmp_path, network=network)

    with pytest.raises(pocketforge.SeedRefused) as exc:
        pocketforge.load_seed(tmp_path)

    assert "printable ASCII" in str(exc.value)


def test_render_wpa_uses_only_ext_password_and_world_domain_warning(tmp_path):
    network = VALID_NETWORK_CONFIG.replace("    regulatory-domain: GB\n", "")
    _write_seed(tmp_path, network=network)
    seed = pocketforge.load_seed(tmp_path)

    rendered = pocketforge.render_wpa_config(seed.network_config)

    assert "country=00" in rendered.content
    assert rendered.warning == "regulatory domain omitted; using 00"
    assert "ext_password_backend=file:/run/credentials/" in rendered.content
    assert "psk=ext:net00" in rendered.content
    assert "correct horse battery staple" not in rendered.content
    assert 'psk="' not in rendered.content
    assert 'bgscan="learn:60:-72:600:' in rendered.content


def test_multiple_access_points_use_deterministic_credential_names(tmp_path):
    network = VALID_NETWORK_CONFIG.replace(
        "      Bench Network:\n"
        "        password: correct horse battery staple\n",
        "      Zebra Network:\n"
        "        password: zebra horse battery staple\n"
        "      Alpha Network:\n"
        "        password: alpha horse battery staple\n",
    )
    _write_seed(tmp_path, network=network)
    seed = pocketforge.load_seed(tmp_path)

    credentials = pocketforge.derive_wifi_credentials(seed.network_config)
    redacted = pocketforge.redacted_network_config(seed.network_config)
    rendered = pocketforge.render_wpa_config(seed.network_config)

    expected_alpha = hashlib.pbkdf2_hmac(
        "sha1", b"alpha horse battery staple", b"Alpha Network", 4096, 32
    ).hex()
    assert credentials["net00"] == expected_alpha
    assert redacted["wifis"]["wlan0"]["access-points"]["Alpha Network"] == {
        "password": "ext:net00"
    }
    assert rendered.content.index("416c706861204e6574776f726b") < (
        rendered.content.index("5a65627261204e6574776f726b")
    )


def test_install_encrypted_credential_is_atomic_and_stdin_only(
    tmp_path, mocker
):
    _write_seed(tmp_path)
    seed = pocketforge.load_seed(tmp_path)
    target = tmp_path / "root"
    calls = []

    def fake_subp(args, *, data, logstring, capture):
        calls.append((args, data, logstring, capture))
        Path(args[-1]).write_bytes(b"encrypted credential")

    mocker.patch("cloudinit.pocketforge.subp.subp", side_effect=fake_subp)

    pocketforge.install_wifi(seed, target=target)

    assert len(calls) == 1
    args, stdin, logstring, capture = calls[0]
    assert args[:5] == [
        "systemd-creds",
        "encrypt",
        "--with-key=host",
        "--name=wpa-psks",
        "-",
    ]
    assert "correct horse battery staple" not in " ".join(args)
    assert "correct horse battery staple" not in logstring
    assert stdin == (
        "net00="
        + hashlib.pbkdf2_hmac(
            "sha1",
            b"correct horse battery staple",
            b"Bench Network",
            4096,
            32,
        ).hex()
        + "\n"
    )
    credential = target / "etc/credstore.encrypted/wpa-psks"
    wpa = target / "etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
    assert credential.read_bytes() == b"encrypted credential"
    assert credential.stat().st_mode & 0o777 == 0o600
    assert wpa.stat().st_mode & 0o777 == 0o600
    assert "correct horse battery staple" not in wpa.read_text()


def test_failed_credential_install_leaves_no_target_writes(tmp_path, mocker):
    _write_seed(tmp_path)
    seed = pocketforge.load_seed(tmp_path)
    target = tmp_path / "root"

    def fail_subp(args, *, data, logstring, capture):
        raise RuntimeError("encryption failed")

    mocker.patch("cloudinit.pocketforge.subp.subp", side_effect=fail_subp)

    with pytest.raises(RuntimeError, match="encryption failed"):
        pocketforge.install_wifi(seed, target=target)

    assert not (target / "etc/credstore.encrypted/wpa-psks").exists()
    assert not (
        target / "etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
    ).exists()


def test_finalize_burns_secret_in_place_and_writes_secret_free_status(
    tmp_path,
):
    _write_seed(tmp_path)
    seed = pocketforge.load_seed(tmp_path)
    network_path = tmp_path / "network-config"
    inode = network_path.stat().st_ino

    status = pocketforge.finalize_seed(
        seed,
        pocketforge.Status(
            state="applied",
            instance_id="bench-001",
            applied=["wifi", "ssh"],
            wifi_ssids=["Bench Network"],
            regulatory_domain="GB",
            ssh_key_fingerprints=["SHA256:public-only"],
        ),
    )

    raw = network_path.read_bytes()
    assert network_path.stat().st_ino == inode
    assert b"correct horse battery staple" not in raw
    assert b"removed by PocketForge" in raw
    assert "correct horse battery staple" not in status.text
    assert "correct horse battery staple" not in status.json
    assert json.loads(status.json)["state"] == "applied"
    assert (tmp_path / "cloud-init-status.txt").stat().st_mode & 0o777 == 0o600
    assert (
        tmp_path / "cloud-init-status.json"
    ).stat().st_mode & 0o777 == 0o600


def test_finalize_writes_generated_metadata_after_validation(tmp_path):
    _write_seed(tmp_path)
    (tmp_path / "meta-data").unlink()
    seed = pocketforge.load_seed(tmp_path)

    pocketforge.finalize_seed(
        seed,
        pocketforge.Status(
            state="applied",
            instance_id=seed.metadata["instance-id"],
            applied=["wifi", "ssh"],
            wifi_ssids=["Bench Network"],
            regulatory_domain="GB",
            ssh_key_fingerprints=["SHA256:public-only"],
        ),
    )

    assert (tmp_path / "meta-data").read_text() == seed.metadata_text


@pytest.mark.parametrize(
    "status",
    [
        pocketforge.Status(
            state="applied",
            instance_id="i",
            applied=[],
            wifi_ssids=[],
            regulatory_domain="00",
            ssh_key_fingerprints=[],
            detail="password=secret-value",
        ),
        pocketforge.Status(
            state="applied",
            instance_id="i",
            applied=[],
            wifi_ssids=[],
            regulatory_domain="00",
            ssh_key_fingerprints=[],
            detail="psk=0123456789abcdef" * 4,
        ),
    ],
)
def test_status_refuses_secret_shaped_content(status):
    with pytest.raises(ValueError, match="secret-shaped"):
        pocketforge.render_status(status)


def test_burn_failure_does_not_report_applied(tmp_path, mocker):
    _write_seed(tmp_path)
    seed = pocketforge.load_seed(tmp_path)
    mocker.patch(
        "cloudinit.pocketforge._overwrite_secret_spans",
        side_effect=OSError("read-only filesystem"),
    )

    with pytest.raises(OSError, match="read-only filesystem"):
        pocketforge.finalize_seed(
            seed,
            pocketforge.Status(
                state="applied",
                instance_id="bench-001",
                applied=["wifi"],
                wifi_ssids=["Bench Network"],
                regulatory_domain="GB",
                ssh_key_fingerprints=[],
            ),
        )

    assert not (tmp_path / "cloud-init-status.txt").exists()
    assert not (tmp_path / "cloud-init-status.json").exists()


def test_refusal_status_leaves_all_seed_inputs_byte_identical(tmp_path):
    _write_seed(
        tmp_path,
        user_data=VALID_USER_DATA.replace(
            "ssh_pwauth: false", "ssh_pwauth: true"
        ),
    )
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    with pytest.raises(pocketforge.SeedRefused) as caught:
        pocketforge.load_seed(tmp_path)

    pocketforge.write_refusal_status(tmp_path, caught.value)

    assert before == {name: (tmp_path / name).read_bytes() for name in before}
    status = (tmp_path / "cloud-init-status.json").read_text()
    assert "refused" in status
    assert "ssh_pwauth" in status
    assert "correct horse battery staple" not in status


def test_schema_refusal_status_does_not_echo_invalid_value(tmp_path):
    secret_canary = "schema-status-secret-canary"
    _write_seed(
        tmp_path,
        user_data=VALID_USER_DATA + f"timezone: [{secret_canary}]\n",
    )
    with pytest.raises(pocketforge.SeedRefused) as caught:
        pocketforge.load_seed(tmp_path)

    pocketforge.write_refusal_status(tmp_path, caught.value)

    refusal = str(caught.value)
    status = (tmp_path / "cloud-init-status.json").read_text()
    assert "timezone" in refusal
    assert secret_canary not in refusal
    assert secret_canary not in status


def test_setup_rejected_record_is_typed_and_secret_free(tmp_path):
    refusal = pocketforge.SeedRefused(
        [pocketforge.PolicyProblem("user-data", 7, "ssh_pwauth is refused")]
    )

    path = pocketforge.write_setup_rejected(refusal, runtime_dir=tmp_path)

    record = json.loads(path.read_text())
    assert record == {
        "condition": "SetupRejected",
        "problems": [
            {
                "filename": "user-data",
                "line": 7,
                "message": "ssh_pwauth is refused",
            }
        ],
        "schema": "pocketforge.setup.v1",
        "state": "active",
    }
    assert path.stat().st_mode & 0o777 == 0o644


def test_pocketforge_distro_disables_fallback_network(paths):
    from cloudinit.distros.pocketforge import Distro

    distro = Distro("pocketforge", {}, paths)

    assert distro.generate_fallback_config() is None


def test_written_files_are_not_group_or_world_readable(tmp_path, mocker):
    _write_seed(tmp_path)
    seed = pocketforge.load_seed(tmp_path)
    target = tmp_path / "root"

    def fake_subp(args, *, data, logstring, capture):
        Path(args[-1]).write_bytes(b"encrypted")

    mocker.patch("cloudinit.pocketforge.subp.subp", side_effect=fake_subp)
    pocketforge.install_wifi(seed, target=target)

    for path in target.rglob("*"):
        if path.is_file():
            assert os.stat(path).st_mode & 0o077 == 0


def test_internal_network_schema_accepts_redacted_wifi_contract():
    schema_path = (
        Path(__file__).parents[2]
        / "cloudinit/config/schemas/schema-network-config-v2.json"
    )
    schema = json.loads(schema_path.read_text())
    Draft7Validator.check_schema(schema)

    Draft7Validator(schema).validate(
        {
            "version": 2,
            "wifis": {
                "wlan0": {
                    "dhcp4": True,
                    "regulatory-domain": "GB",
                    "access-points": {"Bench": {"password": "ext:net00"}},
                }
            },
        }
    )
