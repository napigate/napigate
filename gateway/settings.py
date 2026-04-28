from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import logging
import os
from pathlib import Path


LOGGER = logging.getLogger("gateway.settings")
DEFAULT_ENV_PATH = Path(".env")


def load_env_file(path: Path | str = DEFAULT_ENV_PATH, *, override: bool = False) -> None:
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if value and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]

        if override or key not in os.environ:
            os.environ[key] = value


@dataclass(slots=True)
class BasicAuthSettings:
    username: str = ""
    password: str = ""
    realm: str = "NapiGate Admin"

    @property
    def enabled(self) -> bool:
        return bool(self.username and self.password)


@dataclass(slots=True)
class AppSettings:
    admin_auth: BasicAuthSettings
    admin_access_allowlist: list[str]
    redis_url: str = ""


def get_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value != "":
            return value
    return default


def load_settings() -> AppSettings:
    username = get_env("NAPIGATE_ADMIN_USERNAME", "APIGATE_ADMIN_USERNAME").strip()
    password = get_env("NAPIGATE_ADMIN_PASSWORD", "APIGATE_ADMIN_PASSWORD").strip()
    raw_allowlist = get_env("NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS").strip()

    if bool(username) != bool(password):
        LOGGER.warning(
            "Admin auth configuration is incomplete. Both NAPIGATE_ADMIN_USERNAME and "
            "NAPIGATE_ADMIN_PASSWORD must be set to enable protection."
        )

    allowlist: list[str] = []
    for item in raw_allowlist.replace("\n", ",").split(","):
        entry = item.strip()
        if not entry:
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS contains invalid IP/CIDR '{entry}'."
            ) from exc
        if entry not in allowlist:
            allowlist.append(entry)

    redis_url = get_env("NAPIGATE_REDIS_URL").strip()

    return AppSettings(
        admin_auth=BasicAuthSettings(
            username=username,
            password=password,
            realm="NapiGate Admin",
        ),
        admin_access_allowlist=allowlist,
        redis_url=redis_url,
    )
