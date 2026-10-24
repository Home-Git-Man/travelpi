"""The media server the TV remote browses: Plex (plexlib.py, /etc/travelpi/plex.env) or Jellyfin (jellyfin.py,
/etc/travelpi/jellyfin.env) – whichever is set up (Plex first if both). install.sh asks which one you use."""
from __future__ import annotations

from types import ModuleType
from typing import Any

from . import jellyfin, plexlib


def backend() -> tuple[str, ModuleType | None]:
    if plexlib.enabled():
        return "Plex", plexlib
    if jellyfin.enabled():
        return "Jellyfin", jellyfin
    return "", None


def name() -> str:
    return backend()[0]


def _need() -> ModuleType:
    mod = backend()[1]
    if mod is None:
        raise ValueError("No media server is set up on this router (Plex or Jellyfin – see the installer)")
    return mod


def browse(view: str, key: str = "", q: str = "") -> dict[str, Any]:
    return _need().browse(view, key, q)


def thumb(path: str) -> tuple[bytes, str]:
    return _need().thumb(path)


def stream(key: str) -> tuple[str, int]:
    return _need().stream(key)
