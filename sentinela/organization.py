"""The simulated organization: the computers and servers the SOC is defending."""
import json
import threading
import uuid
from pathlib import Path
from typing import Optional

from .models import Asset, AssetIn

SAMPLE_ASSETS = [
    AssetIn(hostname="WS-ALICE", ip="10.0.1.11", os="Windows 11", role="workstation",
            department="Finance", criticality="low", users=["alice"]),
    AssetIn(hostname="WS-BOB", ip="10.0.1.12", os="Windows 11", role="workstation",
            department="Sales", criticality="low", users=["bob"]),
    AssetIn(hostname="WS-CAROL", ip="10.0.1.13", os="Windows 11", role="workstation",
            department="HR", criticality="low", users=["carol"]),
    AssetIn(hostname="WS-DAVE", ip="10.0.1.14", os="Windows 11", role="workstation",
            department="Engineering", criticality="low", users=["dave"]),
    AssetIn(hostname="WS-IT01", ip="10.0.1.20", os="Windows 11", role="workstation",
            department="IT", criticality="medium", users=["it-admin"]),
    AssetIn(hostname="DC01", ip="10.0.0.10", os="Windows Server 2022", role="domain_controller",
            department="IT", criticality="high", users=["administrator", "it-admin"]),
    AssetIn(hostname="WEB01", ip="10.0.0.20", os="Ubuntu 22.04", role="web_server",
            department="IT", criticality="high", users=["root", "www-data"]),
    AssetIn(hostname="DB01", ip="10.0.0.30", os="Windows Server 2022", role="database",
            department="Finance", criticality="high", users=["administrator", "sqlsvc"]),
]


class Organization:
    """Stores assets in memory and, when a path is given, saves them to a JSON file."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path
        self._lock = threading.RLock()
        self._assets: dict[str, Asset] = {}
        if path and path.exists():
            self._load()
        else:
            self._assets = self._sample()  # not saved until the first change

    # --- Persistence ---

    @staticmethod
    def _sample() -> dict[str, Asset]:
        assets = [Asset(id=_new_id(), **data.model_dump()) for data in SAMPLE_ASSETS]
        return {asset.id: asset for asset in assets}

    def _load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._assets = {item["id"]: Asset(**item) for item in data["assets"]}
        except (OSError, ValueError, KeyError, TypeError) as e:
            print(f"[-] Could not read {self.path} ({e}); using the sample organization.")
            self._assets = self._sample()

    def _save(self):
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"assets": [asset.model_dump(mode="json") for asset in self._assets.values()]}
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # --- Queries ---

    def all(self) -> list[Asset]:
        with self._lock:
            return list(self._assets.values())

    def get(self, asset_id: str) -> Optional[Asset]:
        return self._assets.get(asset_id)

    def find_by_hostname(self, hostname: str) -> Optional[Asset]:
        hostname = hostname.lower()
        return next((a for a in self.all() if a.hostname.lower() == hostname), None)

    # --- Changes ---

    def _check_unique(self, data: AssetIn, ignore_id: Optional[str] = None):
        for asset in self._assets.values():
            if asset.id == ignore_id:
                continue
            if asset.hostname.lower() == data.hostname.lower():
                raise ValueError(f"Hostname '{data.hostname}' is already used.")
            if asset.ip == data.ip:
                raise ValueError(f"IP {data.ip} is already used by {asset.hostname}.")

    def add(self, data: AssetIn) -> Asset:
        with self._lock:
            self._check_unique(data)
            asset = Asset(id=_new_id(), **data.model_dump())
            self._assets[asset.id] = asset
            self._save()
            return asset

    def update(self, asset_id: str, data: AssetIn) -> Optional[Asset]:
        with self._lock:
            if asset_id not in self._assets:
                return None
            self._check_unique(data, ignore_id=asset_id)
            asset = Asset(id=asset_id, **data.model_dump())
            self._assets[asset_id] = asset
            self._save()
            return asset

    def remove(self, asset_id: str) -> bool:
        with self._lock:
            if self._assets.pop(asset_id, None) is None:
                return False
            self._save()
            return True

    def reset_to_sample(self):
        with self._lock:
            self._assets = self._sample()
            self._save()


def is_linux(asset: Asset) -> bool:
    return any(word in asset.os.lower() for word in ("linux", "ubuntu", "debian", "centos", "red hat"))


def _new_id() -> str:
    return uuid.uuid4().hex[:8]
