# Copyright (C) 2026 PocketForge contributors.
#
# This file is part of cloud-init. See LICENSE file for license information.

"""Strict first-boot seed handling for the PocketForge NoCloud profile.

The functions in this module deliberately separate validation from writes.
Callers must complete :func:`load_seed` before applying any part of a seed.
Secret values are never included in exceptions, status, or object reprs.
"""

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple, Union

from cloudinit import atomic_helper, safeyaml, subp, util

SEED_VARIANTS = ("", ".txt", ".yaml", ".yml")
REQUIRED_SEED_FILES = ("user-data", "network-config")
OPTIONAL_SEED_FILES = ("meta-data",)
FORBIDDEN_SEED_FILES = ("vendor-data",)
MAX_SEED_FILE_SIZE = 1024 * 1024
REDACTION = "<removed by PocketForge>"

ALLOWED_USER_DATA_KEYS = {
    "bootcmd",
    "disable_root",
    "fqdn",
    "hostname",
    "keyboard",
    "locale",
    "preserve_hostname",
    "runcmd",
    "ssh_authorized_keys",
    "ssh_pwauth",
    "timezone",
    "users",
    "write_files",
}
ALLOWED_USER_KEYS = {"lock_passwd", "name", "ssh_authorized_keys"}
ALLOWED_METADATA_KEYS = {"instance-id", "local-hostname"}
ALLOWED_NETWORK_KEYS = {"version", "wifis"}
ALLOWED_WIFI_KEYS = {
    "access-points",
    "dhcp4",
    "dhcp6",
    "optional",
    "regulatory-domain",
}
ALLOWED_ACCESS_POINT_KEYS = {"password", "password-b64"}

_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_PMK_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SECRET_STATUS_RE = re.compile(
    r"(?i)(?:password(?:-b64)?|passphrase|private[-_ ]?key|psk)\s*[:=]"
    r"|\b[0-9a-f]{64}\b"
)


@dataclass(frozen=True)
class PolicyProblem:
    filename: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.filename}:{self.line}: {self.message}"


class SeedRefused(ValueError):
    """A complete seed was rejected before any target write."""

    def __init__(self, problems: List[PolicyProblem]):
        self.problems = tuple(problems)
        super().__init__("; ".join(str(problem) for problem in problems))


@dataclass(repr=False)
class Seed:
    root: Path
    paths: Dict[str, Path]
    user_data: str
    user_config: dict
    network_text: str
    network_config: dict
    metadata_text: str
    metadata: dict
    generated_metadata: bool = False

    def __repr__(self) -> str:
        return "Seed(root={!r}, files={!r}, instance_id={!r})".format(
            str(self.root),
            sorted(path.name for path in self.paths.values()),
            self.metadata.get("instance-id"),
        )


@dataclass(frozen=True)
class RenderedWpa:
    content: str
    warning: Optional[str] = None


@dataclass(frozen=True)
class Status:
    state: str
    instance_id: str
    applied: List[str]
    wifi_ssids: List[str]
    regulatory_domain: str
    ssh_key_fingerprints: List[str]
    detail: str = ""
    version: int = 1


@dataclass(frozen=True)
class RenderedStatus:
    text: str
    json: str


def _variants(name: str) -> Tuple[str, ...]:
    return tuple(name + suffix for suffix in SEED_VARIANTS)


def _find_seed_file(root: Path, name: str) -> Optional[Path]:
    found = [root / candidate for candidate in _variants(name)]
    found = [path for path in found if path.exists()]
    if len(found) > 1:
        raise SeedRefused(
            [
                PolicyProblem(
                    name,
                    1,
                    "duplicate variants: "
                    + ", ".join(path.name for path in found),
                )
            ]
        )
    if not found:
        return None
    path = found[0]
    if path.is_symlink() or not path.is_file():
        raise SeedRefused(
            [PolicyProblem(path.name, 1, "seed entry is not a regular file")]
        )
    if path.stat().st_size > MAX_SEED_FILE_SIZE:
        raise SeedRefused(
            [PolicyProblem(path.name, 1, "seed file exceeds 1 MiB")]
        )
    return path


def _normalized_text(path: Path) -> str:
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise SeedRefused(
            [PolicyProblem(path.name, error.start + 1, "invalid UTF-8")]
        ) from error
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _instance_id_payload(user_config: dict, network_config: dict) -> bytes:
    """Return canonical logical seed data with Wi-Fi secrets removed."""

    network = copy.deepcopy(network_config)
    if isinstance(network, dict):
        wifis = network.get("wifis", {})
        if isinstance(wifis, dict):
            for wifi in wifis.values():
                if not isinstance(wifi, dict):
                    continue
                access_points = wifi.get("access-points", {})
                if not isinstance(access_points, dict):
                    continue
                for access_point in access_points.values():
                    if not isinstance(access_point, dict):
                        continue
                    access_point.pop("password", None)
                    access_point.pop("password-b64", None)
    return json.dumps(
        {"user-data": user_config, "network-config": network},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _load_yaml(filename: str, text: str) -> Tuple[dict, Dict[str, int]]:
    if "\t" in text:
        line = text[: text.index("\t")].count("\n") + 1
        raise SeedRefused(
            [PolicyProblem(filename, line, "tabs are not allowed in YAML")]
        )
    try:
        value, marks = safeyaml.load_with_marks(text)
    except Exception as error:
        mark = getattr(error, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 1
        raise SeedRefused(
            [PolicyProblem(filename, line, "invalid YAML")]
        ) from error
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise SeedRefused(
            [PolicyProblem(filename, 1, "top-level value must be a mapping")]
        )
    return value, marks


def _problem(
    filename: str, marks: Mapping[str, int], path: str, message: str
) -> PolicyProblem:
    return PolicyProblem(filename, marks.get(path, 1), message)


def _safe_schema_message(path: str, message: str) -> str:
    """Describe a schema error without echoing configuration values."""

    if message.startswith("Additional properties"):
        unexpected = re.search(r"\('([^']+)' was unexpected\)", message)
        if unexpected:
            return f"unknown field {unexpected.group(1)}"
    return f"{path or 'cloud-config'} does not match its schema"


def _validate_user_data(
    filename: str, text: str, config: dict, marks: Mapping[str, int]
) -> List[PolicyProblem]:
    # Imported lazily to avoid schema -> stages -> distro import cycles during
    # cloud-init's renderer and distro discovery.
    from cloudinit.config.schema import (
        SchemaValidationError,
        validate_cloudconfig_schema,
    )

    problems = []
    if not text.startswith("#cloud-config\n"):
        content_type = text.splitlines()[0] if text.splitlines() else "empty"
        if content_type.startswith("#include"):
            message = "#include and network fetches are not allowed"
        else:
            message = "only #cloud-config user-data is allowed"
        problems.append(PolicyProblem(filename, 1, message))
        return problems

    for key in config:
        if key not in ALLOWED_USER_DATA_KEYS:
            problems.append(
                _problem(
                    filename, marks, key, f"unknown or disabled key {key}"
                )
            )

    try:
        validate_cloudconfig_schema(
            config=config,
            strict=True,
            log_details=False,
            log_deprecations=False,
        )
    except SchemaValidationError as error:
        for schema_problem in (error.schema_errors or []) + (
            error.schema_deprecations or []
        ):
            problems.append(
                _problem(
                    filename,
                    marks,
                    schema_problem.path,
                    _safe_schema_message(
                        schema_problem.path, schema_problem.message
                    ),
                )
            )

    if config.get("ssh_pwauth") is not False:
        if "ssh_pwauth" in config:
            problems.append(
                _problem(
                    filename,
                    marks,
                    "ssh_pwauth",
                    "ssh_pwauth must be false; SSH is key-only",
                )
            )
    if config.get("disable_root") is not True:
        if "disable_root" in config:
            problems.append(
                _problem(
                    filename,
                    marks,
                    "disable_root",
                    "disable_root must be true",
                )
            )

    users = config.get("users", [])
    if not isinstance(users, list):
        problems.append(
            _problem(filename, marks, "users", "users must be a list")
        )
        return problems
    for index, user in enumerate(users):
        path = f"users.{index}"
        if not isinstance(user, dict):
            problems.append(
                _problem(filename, marks, path, "user must be a mapping")
            )
            continue
        for key in user:
            if key not in ALLOWED_USER_KEYS:
                problems.append(
                    _problem(
                        filename,
                        marks,
                        f"{path}.{key}",
                        f"unknown or refused user key {key}",
                    )
                )
        if user.get("name") != "gamer":
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.name",
                    "Stage A accepts only the gamer user",
                )
            )
        if user.get("lock_passwd") is not True:
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.lock_passwd",
                    "gamer password must remain locked",
                )
            )
    return problems


def _validate_metadata(
    filename: str, config: dict, marks: Mapping[str, int]
) -> List[PolicyProblem]:
    problems = []
    for key in config:
        if key not in ALLOWED_METADATA_KEYS:
            hint = (
                "; did you mean instance-id?" if key == "instance_id" else ""
            )
            problems.append(
                _problem(
                    filename,
                    marks,
                    key,
                    f"unknown metadata key {key}{hint}",
                )
            )
    return problems


def _secret_from_ap(
    filename: str,
    marks: Mapping[str, int],
    path: str,
    ap: dict,
) -> Tuple[Optional[bytes], List[PolicyProblem]]:
    problems = []
    present = [key for key in ALLOWED_ACCESS_POINT_KEYS if key in ap]
    if len(present) != 1:
        problems.append(
            _problem(
                filename,
                marks,
                path,
                "access point must contain exactly one of password or "
                "password-b64",
            )
        )
        return None, problems
    key = present[0]
    value = ap[key]
    if not isinstance(value, str):
        problems.append(
            _problem(filename, marks, f"{path}.{key}", f"{key} must be text")
        )
        return None, problems
    if key == "password-b64":
        try:
            secret = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.{key}",
                    "password-b64 is not strict base64",
                )
            )
            return None, problems
    else:
        try:
            secret = value.encode("utf-8")
        except UnicodeEncodeError:
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.{key}",
                    "password is not valid UTF-8",
                )
            )
            return None, problems
    if not _PMK_RE.fullmatch(secret.decode("ascii", errors="ignore")):
        if not 8 <= len(secret) <= 63:
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.{key}",
                    "WPA passphrase must contain 8 through 63 bytes",
                )
            )
        elif any(byte < 0x20 or byte > 0x7E for byte in secret):
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.{key}",
                    "WPA passphrase must contain printable ASCII only",
                )
            )
    return secret, problems


def _validate_network(
    filename: str, config: dict, marks: Mapping[str, int]
) -> List[PolicyProblem]:
    problems = []
    for key in config:
        if key not in ALLOWED_NETWORK_KEYS:
            problems.append(
                _problem(filename, marks, key, f"unknown or refused key {key}")
            )
    if config.get("version") != 2:
        problems.append(
            _problem(
                filename, marks, "version", "network-config must use version 2"
            )
        )
    wifis = config.get("wifis")
    if not isinstance(wifis, dict) or not wifis:
        problems.append(
            _problem(filename, marks, "wifis", "wifis must be a mapping")
        )
        return problems
    if set(wifis) != {"wlan0"}:
        problems.append(
            _problem(filename, marks, "wifis", "Stage A allows only wlan0")
        )
    for interface, wifi in wifis.items():
        path = f"wifis.{interface}"
        if not isinstance(wifi, dict):
            problems.append(
                _problem(
                    filename, marks, path, "Wi-Fi config must be a mapping"
                )
            )
            continue
        for key in wifi:
            if key not in ALLOWED_WIFI_KEYS:
                problems.append(
                    _problem(
                        filename,
                        marks,
                        f"{path}.{key}",
                        f"unknown or refused Wi-Fi key {key}",
                    )
                )
        country = wifi.get("regulatory-domain")
        if country is not None and (
            not isinstance(country, str)
            or _COUNTRY_RE.fullmatch(country.upper()) is None
        ):
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.regulatory-domain",
                    "regulatory-domain must be two ASCII letters",
                )
            )
        access_points = wifi.get("access-points")
        if not isinstance(access_points, dict) or not access_points:
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.access-points",
                    "access-points must be a non-empty mapping",
                )
            )
            continue
        if len(access_points) > 100:
            problems.append(
                _problem(
                    filename,
                    marks,
                    f"{path}.access-points",
                    "at most 100 access points are allowed",
                )
            )
        for ssid, ap in access_points.items():
            ap_path = f"{path}.access-points.{ssid}"
            if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32:
                problems.append(
                    _problem(
                        filename,
                        marks,
                        ap_path,
                        "SSID must contain 1 through 32 bytes",
                    )
                )
                continue
            if not isinstance(ap, dict):
                problems.append(
                    _problem(
                        filename,
                        marks,
                        ap_path,
                        "access point config must be a mapping",
                    )
                )
                continue
            for key in ap:
                if key not in ALLOWED_ACCESS_POINT_KEYS:
                    problems.append(
                        _problem(
                            filename,
                            marks,
                            f"{ap_path}.{key}",
                            f"unknown or refused access-point key {key}",
                        )
                    )
            _secret, secret_problems = _secret_from_ap(
                filename, marks, ap_path, ap
            )
            problems.extend(secret_problems)
    return problems


def load_seed(root: Union[str, Path]) -> Seed:
    """Load and validate a complete PocketForge seed without target writes."""

    root = Path(root)
    paths = {}
    problems = []
    for name in REQUIRED_SEED_FILES + OPTIONAL_SEED_FILES:
        path = _find_seed_file(root, name)
        if path is not None:
            paths[name] = path
        elif name in REQUIRED_SEED_FILES:
            problems.append(
                PolicyProblem(name, 1, "required seed file missing")
            )
    for name in FORBIDDEN_SEED_FILES:
        path = _find_seed_file(root, name)
        if path is not None:
            problems.append(
                PolicyProblem(path.name, 1, "vendor-data is not allowed")
            )
    if problems:
        raise SeedRefused(problems)

    user_text = _normalized_text(paths["user-data"])
    network_text = _normalized_text(paths["network-config"])
    if not user_text.startswith("#cloud-config\n"):
        content_type = (
            user_text.splitlines()[0] if user_text.splitlines() else "empty"
        )
        if content_type.startswith("#include"):
            message = "#include and network fetches are not allowed"
        else:
            message = "only #cloud-config user-data is allowed"
        raise SeedRefused([PolicyProblem(paths["user-data"].name, 1, message)])
    user_config, user_marks = _load_yaml(paths["user-data"].name, user_text)
    network_config, network_marks = _load_yaml(
        paths["network-config"].name, network_text
    )
    problems.extend(
        _validate_user_data(
            paths["user-data"].name, user_text, user_config, user_marks
        )
    )
    problems.extend(
        _validate_network(
            paths["network-config"].name, network_config, network_marks
        )
    )

    generated_metadata = "meta-data" not in paths
    if generated_metadata:
        logical_digest = hashlib.sha256(
            _instance_id_payload(user_config, network_config)
        ).hexdigest()
        metadata = {"instance-id": f"pf-{logical_digest[:16]}"}
        metadata_text = "instance-id: {}\n".format(metadata["instance-id"])
    else:
        metadata_text = _normalized_text(paths["meta-data"])
        metadata, metadata_marks = _load_yaml(
            paths["meta-data"].name, metadata_text
        )
        problems.extend(
            _validate_metadata(
                paths["meta-data"].name, metadata, metadata_marks
            )
        )
        instance_id = metadata.get("instance-id")
        if not isinstance(instance_id, str) or not instance_id.strip():
            problems.append(
                _problem(
                    paths["meta-data"].name,
                    metadata_marks,
                    "instance-id",
                    "instance-id must be non-empty text",
                )
            )
    if problems:
        raise SeedRefused(problems)
    return Seed(
        root=root,
        paths=paths,
        user_data=user_text,
        user_config=user_config,
        network_text=network_text,
        network_config=network_config,
        metadata_text=metadata_text,
        metadata=metadata,
        generated_metadata=generated_metadata,
    )


def derive_wifi_credentials(network_config: dict) -> Dict[str, str]:
    """Return fixed-width external-password names mapped to derived PMKs."""

    credentials = {}
    access_points = network_config["wifis"]["wlan0"]["access-points"]
    for index, ssid in enumerate(sorted(access_points)):
        ap = access_points[ssid]
        secret, problems = _secret_from_ap(
            "network-config",
            {},
            f"wifis.wlan0.access-points.{ssid}",
            ap,
        )
        if problems or secret is None:
            raise SeedRefused(problems)
        if _PMK_RE.fullmatch(secret.decode("ascii", errors="ignore")):
            pmk = secret.decode("ascii").lower()
        else:
            pmk = hashlib.pbkdf2_hmac(
                "sha1", secret, ssid.encode("utf-8"), 4096, 32
            ).hex()
        credentials[f"net{index:02d}"] = pmk
    return credentials


def redacted_network_config(network_config: dict) -> dict:
    """Return network config safe for datasource cache and logs."""

    result = copy.deepcopy(network_config)
    access_points = result["wifis"]["wlan0"]["access-points"]
    for index, ssid in enumerate(sorted(access_points)):
        ap = access_points[ssid]
        ap.pop("password", None)
        ap.pop("password-b64", None)
        ap["password"] = f"ext:net{index:02d}"
    return result


def render_wpa_config(network_config: dict) -> RenderedWpa:
    wifi = network_config["wifis"]["wlan0"]
    country = wifi.get("regulatory-domain")
    warning = None
    if country is None:
        country = "00"
        warning = "regulatory domain omitted; using 00"
    country = country.upper()
    lines = [
        "# Generated by cloud-init for PocketForge.",
        "ctrl_interface=/run/wpa_supplicant",
        "update_config=0",
        f"country={country}",
        "ap_scan=1",
        "bss_expiration_age=600",
        "ext_password_backend=file:/run/credentials/"
        "wpa_supplicant@wlan0.service/wpa-psks",
        "",
    ]
    for index, ssid in enumerate(sorted(wifi["access-points"])):
        safe_ssid = re.sub(r"[^A-Za-z0-9._-]", "_", ssid)
        database = f"/var/lib/wpa_supplicant/bgscan-{safe_ssid}.db"
        lines.extend(
            [
                "network={",
                f"    ssid={ssid.encode('utf-8').hex()}",
                f"    psk=ext:net{index:02d}",
                "    key_mgmt=WPA-PSK",
                "    scan_ssid=1",
                f'    bgscan="learn:60:-72:600:{database}"',
                "}",
                "",
            ]
        )
    return RenderedWpa("\n".join(lines), warning)


def _replace_file(source: Path, destination: Path, mode: int) -> None:
    os.chmod(source, mode)
    os.replace(source, destination)
    os.chmod(destination, mode)


def install_wifi(seed: Seed, target: Union[str, Path] = "/") -> dict:
    """Materialize the encrypted PMK credential and non-secret WPA config.

    The PMK mapping is provided to ``systemd-creds`` only on stdin. The final
    two files become visible through atomic renames after encryption succeeds.
    """

    target = Path(target)
    credentials = derive_wifi_credentials(seed.network_config)
    credential_input = "".join(
        f"{name}={pmk}\n" for name, pmk in credentials.items()
    )
    rendered = render_wpa_config(seed.network_config)
    credential_dir = target / "etc/credstore.encrypted"
    wpa_dir = target / "etc/wpa_supplicant"
    util.ensure_dir(credential_dir, mode=0o700)
    credential_path = credential_dir / "wpa-psks"
    temporary_credential = None
    temporary_wpa = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".wpa-psks.", dir=credential_dir
        )
        os.close(descriptor)
        os.unlink(temporary_name)
        temporary_credential = Path(temporary_name)
        subp.subp(
            [
                "systemd-creds",
                "encrypt",
                "--with-key=host",
                "--name=wpa-psks",
                "-",
                str(temporary_credential),
            ],
            data=credential_input,
            logstring="systemd-creds encrypt [redacted stdin]",
            capture=True,
        )
        if not temporary_credential.is_file():
            raise RuntimeError("systemd-creds did not create its output")

        util.ensure_dir(wpa_dir, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".wpa_supplicant-wlan0.conf.", dir=wpa_dir
        )
        temporary_wpa = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(rendered.content)
            stream.flush()
            os.fsync(stream.fileno())
        _replace_file(temporary_credential, credential_path, 0o600)
        temporary_credential = None
        wpa_path = wpa_dir / "wpa_supplicant-wlan0.conf"
        _replace_file(temporary_wpa, wpa_path, 0o600)
        temporary_wpa = None
    finally:
        for path in (temporary_credential, temporary_wpa):
            if path is not None and path.exists():
                path.unlink()
    return redacted_network_config(seed.network_config)


def _redacted_seed_network(seed: Seed) -> bytes:
    redacted = copy.deepcopy(seed.network_config)
    for ap in redacted["wifis"]["wlan0"]["access-points"].values():
        ap.pop("password", None)
        ap.pop("password-b64", None)
        ap["password"] = REDACTION
    return safeyaml.dumps(
        redacted, explicit_start=False, explicit_end=False, noalias=True
    ).encode("utf-8")


def _overwrite_secret_spans(seed: Seed) -> None:
    """Zero then rewrite the exact validated network file, without rename."""

    path = seed.paths["network-config"]
    before = path.stat()
    if path.is_symlink() or not path.is_file():
        raise OSError("validated network-config is no longer a regular file")
    redacted = _redacted_seed_network(seed)
    with path.open("r+b", buffering=0) as stream:
        stream.write(b"\0" * before.st_size)
        os.fsync(stream.fileno())
        stream.seek(0)
        stream.write(redacted)
        stream.truncate()
        os.fsync(stream.fileno())
    after = path.stat()
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise OSError("seed file identity changed during overwrite")


def render_status(status: Status) -> RenderedStatus:
    data = asdict(status)
    serialized = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if _SECRET_STATUS_RE.search(serialized):
        raise ValueError("status contains secret-shaped content")
    lines = [
        f"state={status.state}",
        f"instance-id={status.instance_id}",
        "applied=" + ",".join(status.applied),
        "wifi-ssids=" + ",".join(status.wifi_ssids),
        f"regulatory-domain={status.regulatory_domain}",
        "ssh-key-fingerprints=" + ",".join(status.ssh_key_fingerprints),
    ]
    if status.detail:
        lines.append(f"detail={status.detail}")
    text = "\n".join(lines) + "\n"
    if _SECRET_STATUS_RE.search(text):
        raise ValueError("status contains secret-shaped content")
    return RenderedStatus(text, serialized)


def finalize_seed(seed: Seed, status: Status) -> RenderedStatus:
    """Burn accepted secret input, then write the non-secret status files."""

    rendered = render_status(status)
    _overwrite_secret_spans(seed)
    if seed.generated_metadata:
        metadata_path = seed.root / "meta-data"
        descriptor = os.open(
            metadata_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(seed.metadata_text)
            stream.flush()
            os.fsync(stream.fileno())
    text_path = seed.root / "cloud-init-status.txt"
    json_path = seed.root / "cloud-init-status.json"
    atomic_helper.write_file(
        str(text_path), rendered.text, mode=0o600, omode="w"
    )
    atomic_helper.write_file(
        str(json_path), rendered.json, mode=0o600, omode="w"
    )
    return rendered


def write_refusal_status(
    root: Union[str, Path], refusal: SeedRefused
) -> RenderedStatus:
    """Write a non-secret refusal while leaving every seed input untouched."""

    root = Path(root)
    rendered = render_status(
        Status(
            state="refused",
            instance_id="pocketforge-rejected",
            applied=[],
            wifi_ssids=[],
            regulatory_domain="00",
            ssh_key_fingerprints=[],
            detail="; ".join(str(problem) for problem in refusal.problems),
        )
    )
    atomic_helper.write_file(
        str(root / "cloud-init-status.txt"),
        rendered.text,
        mode=0o600,
        omode="w",
    )
    atomic_helper.write_file(
        str(root / "cloud-init-status.json"),
        rendered.json,
        mode=0o600,
        omode="w",
    )
    return rendered


def write_setup_rejected(
    refusal: SeedRefused,
    runtime_dir: Union[str, Path] = "/run/pocketforge/setup",
) -> Path:
    """Publish a typed, non-secret condition for the screen producer."""

    record = {
        "schema": "pocketforge.setup.v1",
        "condition": "SetupRejected",
        "state": "active",
        "problems": [asdict(problem) for problem in refusal.problems],
    }
    serialized = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if _SECRET_STATUS_RE.search(serialized):
        raise ValueError("SetupRejected record contains secret-shaped content")
    path = Path(runtime_dir) / "SetupRejected.json"
    util.ensure_dir(path.parent, mode=0o755)
    atomic_helper.write_file(str(path), serialized, mode=0o644, omode="w")
    return path
