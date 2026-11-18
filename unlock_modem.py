#!/usr/bin/env python3
"""cancunn-freedom: Build, check, audit, flash, and revert SIM-unlocked MTK md1img.

Default profile is pinned to verified-live Moto G Power 5G (2024) XT2415V (cancunn)
build V1UDS35H.26-14-6-2-11.
Supports dynamic A/B active slot detection, structural microMIPS32 bitmask pattern
scanning across NR15/NR17 branches, automatic profile generation (--emit-profile),
and verified one-command revert.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import time

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import imageaudit  # noqa: E402
import sign_mtk_cert as SMC  # noqa: E402

PROFILES_DIR = ROOT_DIR / "profiles"
DEFAULT_PROFILE = PROFILES_DIR / "cancunn.json"
BACKUPS_DIR = ROOT_DIR / "backups"
WORK_DIR = ROOT_DIR / "work"
DEFAULT_MD1ROM_BASE_VA = 0x90000000


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_profile(profile_path: Path) -> dict:
    if not profile_path.is_file():
        raise FileNotFoundError(f"Profile not found: {profile_path}")
    return json.loads(profile_path.read_text(encoding="utf-8"))


def load_all_profiles() -> list[tuple[Path, dict]]:
    out: list[tuple[Path, dict]] = []
    if PROFILES_DIR.is_dir():
        for p in sorted(PROFILES_DIR.glob("*.json")):
            try:
                out.append((p, load_profile(p)))
            except Exception:
                continue
    return out


# ---------------------------------------------------------------------------
# Dynamic Active Slot & Device Helpers (ADB / Fastboot)
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], check: bool = False, timeout: float = 5.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, check=check, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, -999, stdout="", stderr=f"Command timed out after {timeout}s"
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(cmd, -1, stdout="", stderr=str(exc))


def detect_adb_info() -> dict[str, str] | None:
    devs = run_cmd(["adb", "devices"], timeout=3.0)
    if devs.returncode != 0:
        return None
    if not any("\tdevice" in line for line in devs.stdout.splitlines()):
        return None

    def getp(prop: str) -> str:
        r = run_cmd(["adb", "shell", "getprop", prop], timeout=3.0)
        return r.stdout.strip() if r.returncode == 0 else ""

    slot = getp("ro.boot.slot_suffix").lstrip("_").lower()
    if slot not in ("a", "b"):
        return None

    return {
        "slot": slot,
        "device": getp("ro.product.device"),
        "model": getp("ro.product.model"),
        "sku": getp("ro.boot.hardware.sku"),
        "build": getp("ro.build.display.id"),
        "baseband": getp("gsm.version.baseband"),
    }


def detect_fastboot_info() -> dict[str, str] | None:
    devs = run_cmd(["fastboot", "devices"], timeout=3.0)
    if devs.returncode != 0 or not devs.stdout.strip():
        return None

    def getv(var: str) -> str:
        r = run_cmd(["fastboot", "getvar", var], timeout=5.0)
        combined = (r.stdout or "") + "\n" + (r.stderr or "")
        for line in combined.splitlines():
            if f"{var.lower()}:" in line.lower():
                return line.split(":", 1)[1].strip()
        return ""

    slot = getv("current-slot").lstrip("_").lower()
    if slot not in ("a", "b"):
        return None

    return {
        "slot": slot,
        "securestate": getv("securestate"),
        "product": getv("product"),
        "sku": getv("sku"),
    }


def detect_slot_adb() -> str | None:
    info = detect_adb_info()
    return info["slot"] if info else None


def detect_slot_fastboot() -> str | None:
    info = detect_fastboot_info()
    return info["slot"] if info else None


def wait_for_fastboot(timeout: float = 30.0) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        info = detect_fastboot_info()
        if info:
            return info
        time.sleep(1.0)
    raise RuntimeError(f"Timed out waiting for device in fastboot mode ({timeout:.0f}s).")


def resolve_target_slot(explicit_slot: str | None, mode: str = "any") -> str:
    if explicit_slot:
        s = explicit_slot.strip().lstrip("_").lower()
        if s not in ("a", "b"):
            raise ValueError(f"Invalid slot '{explicit_slot}' (must be 'a' or 'b').")
        return s

    if mode in ("adb", "any"):
        s = detect_slot_adb()
        if s:
            return s
    if mode in ("fastboot", "any"):
        s = detect_slot_fastboot()
        if s:
            return s

    raise RuntimeError(
        "Could not auto-detect active slot via ADB or Fastboot. "
        "Connect the device or pass '--slot a' / '--slot b' explicitly."
    )


def partition_for_slot(slot: str) -> str:
    s = slot.strip().lstrip("_").lower()
    if s not in ("a", "b"):
        raise ValueError(f"Invalid slot: {slot}")
    return f"md1img_{s}"


def match_profiles_to_device(
    adb_info: dict[str, str] | None,
    fb_info: dict[str, str] | None,
) -> list[tuple[Path, dict]]:
    """Find profiles in profiles/*.json matching the currently connected device."""
    all_profiles = load_all_profiles()
    matched: list[tuple[Path, dict]] = []

    for p_path, prof in all_profiles:
        score = 0
        if adb_info:
            bb = adb_info.get("baseband", "")
            bb_sub = prof.get("baseband_substr", "")
            if bb and bb_sub and bb_sub in bb:
                score += 10
            sku = adb_info.get("sku", "")
            if sku and sku in prof.get("skus", []):
                score += 5
            dev = adb_info.get("device", "")
            if dev and (dev == prof.get("id") or dev in prof.get("models", [])):
                score += 3

        if fb_info:
            sku = fb_info.get("sku", "")
            if sku and sku in prof.get("skus", []):
                score += 5
            prod = fb_info.get("product", "")
            if prod and (prod == prof.get("id") or prod in prof.get("models", [])):
                score += 3

        if score > 0:
            matched.append((p_path, prof))

    return matched


# ---------------------------------------------------------------------------
# MKIMG Trimming, CATI Symbol Resolution & Bitmask Spine Scanner
# ---------------------------------------------------------------------------

def trim_to_mkimg_eof(raw: bytes, quiet: bool = False) -> bytes:
    parts = SMC.parse_part_headers(raw)
    if not parts:
        raise ValueError("Input file has no parseable MTK MKIMG headers (not a valid md1img).")

    eof = parts[-1][3]
    if len(raw) < eof:
        raise ValueError(f"Truncated md1img: file size {len(raw)} < MKIMG EOF {eof}.")
    if len(raw) == eof:
        return raw

    tail = raw[eof:]
    if tail.rstrip(b"\x00"):
        raise ValueError(
            f"Non-zero bytes found past MKIMG EOF ({eof} vs file size {len(raw)}); refusing to trim."
        )
    if not quiet:
        print(f"Trimmed zero-padding: {len(raw)} -> {eof} bytes")
    return raw[:eof]


def find_existing_stock_trimmed(trimmed_size: int, trimmed_sha: str) -> Path | None:
    """Reuse an already-trimmed stock backup in backups/ matching size & SHA-256."""
    if not BACKUPS_DIR.is_dir():
        return None
    for cand in sorted(BACKUPS_DIR.glob("*stock_trimmed*.img")):
        if cand.is_file() and cand.stat().st_size == trimmed_size:
            if sha256_file(cand) == trimmed_sha:
                return cand
    return None


def decompress_dbginfo(raw_dbg: bytes) -> bytes:
    for off in range(min(64, len(raw_dbg))):
        if raw_dbg[off:off + 3] == b"\x5d\x00\x00":
            try:
                return lzma.decompress(raw_dbg[off:])
            except lzma.LZMAError:
                continue
    raise ValueError("Unable to LZMA-decompress md1_dbginfo CATI symbol table.")


def find_cati_symbol(blob: bytes, name: str, base_va: int = DEFAULT_MD1ROM_BASE_VA) -> tuple[int, int] | None:
    needle = name.encode("ascii") + b"\x00"
    matches: list[tuple[int, int]] = []
    idx = 0
    while True:
        hit = blob.find(needle, idx)
        if hit < 0:
            break
        if hit >= 9 and blob[hit - 9] == 0 and hit + len(needle) + 8 <= len(blob):
            _prev, start = struct.unpack_from("<II", blob, hit - 8)
            start2, end = struct.unpack_from("<II", blob, hit + len(needle))
            if start == start2 and base_va <= start < end < (base_va + 0x04000000):
                matches.append((start, end))
        idx = hit + 1
    if len(matches) != 1:
        return None
    return matches[0]


def va_to_file_off(va: int, rom_doff: int, rom_end: int, base_va: int = DEFAULT_MD1ROM_BASE_VA) -> int:
    off = (va - base_va) + rom_doff
    if not (rom_doff <= off < rom_end):
        raise ValueError(f"CATI VA {va:#x} -> offset {off:#x} outside md1rom [{rom_doff:#x}, {rom_end:#x}).")
    return off


def parse_file_map(trimmed: bytes, parts: list) -> dict[str, str]:
    for _idx, _off, doff, _noff, hdr in parts:
        if hdr.name == "md1_file_map":
            txt = trimmed[doff:doff + hdr.dsize].decode("utf-8", errors="replace")
            out: dict[str, str] = {}
            for line in txt.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
            return out
    return {}


def is_valid_micromips_prologue(b4: bytes) -> tuple[bool, str]:
    if len(b4) != 4:
        return False, "invalid-length"
    if b4 == b"\x01\xd2\xe0\xdb":
        return False, "already-patched"
    if b4[1] == 0x1E and b4[3] == 0x12:
        return True, "swm32-prologue"
    if b4 == b"\x49\x1e\x08\x21":
        return True, "save-491e0821"
    if b4[1] == 0x34:
        return True, "addiusp16-prologue"
    return False, f"unrecognized-prologue({b4.hex()})"


def is_bneic_imm1(b4: bytes, expected_first_hw: bytes | None = None) -> bool:
    if len(b4) != 4:
        return False
    if expected_first_hw is not None and b4[:2] != expected_first_hw:
        return False
    return (b4[1] & 0xFC) == 0xC8 and (b4[0] & 0x1F) == 0x10 and (b4[3] & 0xF8) == 0x08


def is_beqic_imm7(b4: bytes) -> bool:
    if len(b4) != 4:
        return False
    return (b4[1] & 0xFC) == 0xC8 and (b4[3] & 0xF8) == 0x38


def is_beqc_reg(b4: bytes) -> bool:
    return len(b4) == 4 and b4[1] == 0x8A


def scan_smu_gates_bitmask(smu_slice: bytes) -> list[tuple[str, int, str, str, str]]:
    candidates: list[list[tuple[str, int, str, str, str]]] = []
    limit = len(smu_slice) - 0x20
    for g2_rel in range(0x24, max(0x24, limit), 2):
        g2 = smu_slice[g2_rel:g2_rel + 4]
        g3 = smu_slice[g2_rel + 0x06:g2_rel + 0x0A]
        g4 = smu_slice[g2_rel + 0x0E:g2_rel + 0x12]
        g5 = smu_slice[g2_rel + 0x12:g2_rel + 0x16]

        if not (
            is_bneic_imm1(g2)
            and is_bneic_imm1(g3, b"\xf0\xc8")
            and is_bneic_imm1(g4, b"\x90\xc8")
            and is_beqic_imm7(g5)
        ):
            continue

        g1_hits = [
            rel1 for rel1 in range(max(0, g2_rel - 0x34), g2_rel - 0x20, 2)
            if is_bneic_imm1(smu_slice[rel1:rel1 + 4], b"\x90\xc8")
        ]
        g5_rel = g2_rel + 0x12
        g6_hits = [
            rel6 for rel6 in (g5_rel + 0x04, g5_rel + 0x06, g5_rel + 0x08)
            if rel6 + 4 <= len(smu_slice) and is_beqc_reg(smu_slice[rel6:rel6 + 4])
        ]

        if len(g1_hits) == 1 and len(g6_hits) >= 1:
            g1_rel = g1_hits[0]
            g6_rel = g6_hits[0]
            candidates.append([
                ("gate-e6ba", g1_rel, smu_slice[g1_rel:g1_rel + 4].hex(), "08900890",
                 f"BNEIC a0,1 early gate (+{g1_rel:#x} in smu_check_sml) -> fall through."),
                ("gate-e6e2", g2_rel, g2.hex(), "08900890",
                 f"BNEIC per-cat verdict (+{g2_rel:#x} in smu_check_sml) -> fall through."),
                ("gate-e6e8", g2_rel + 0x06, g3.hex(), "08900890",
                 f"BNEIC a3,1 status-byte gate (+{g2_rel + 0x06:#x} in smu_check_sml) -> fall through."),
                ("gate-e6f0", g2_rel + 0x0E, g4.hex(), "08900890",
                 f"BNEIC a0,1 cat-choice gate (+{g2_rel + 0x0E:#x} in smu_check_sml) -> fall through."),
                ("gate-e6f4", g5_rel, g5.hex(), "08900890",
                 f"BEQIC cat-accounting gate (+{g5_rel:#x} in smu_check_sml) -> fall through."),
                ("gate-e6f8", g6_rel, smu_slice[g6_rel:g6_rel + 4].hex(), "08900890",
                 f"BEQC verdict-zero gate (+{g6_rel:#x} in smu_check_sml) -> fall through."),
            ])

    return candidates[0] if len(candidates) == 1 else []


def relocate_patches_via_cati(trimmed: bytes) -> tuple[bool, dict, list[dict]]:
    parts = SMC.parse_part_headers(trimmed)
    by_name = {hdr.name: (doff, hdr.dsize) for _idx, _off, doff, _noff, hdr in parts}
    file_map = parse_file_map(trimmed, parts)

    report: dict = {
        "dbginfo_name": file_map.get("md1_dbginfo", "(unknown)"),
        "cati_found": {},
        "checks": [],
        "errors": [],
    }
    if "md1rom" not in by_name or "md1_dbginfo" not in by_name:
        report["errors"].append("Missing md1rom or md1_dbginfo sub-partition.")
        return False, report, []

    rom_doff, rom_dsize = by_name["md1rom"]
    rom_end = rom_doff + rom_dsize
    dbg_doff, dbg_dsize = by_name["md1_dbginfo"]

    try:
        blob = decompress_dbginfo(trimmed[dbg_doff:dbg_doff + dbg_dsize])
    except ValueError as exc:
        report["errors"].append(str(exc))
        return False, report, []

    patches: list[dict] = []
    all_ok = True

    prologue_targets = (
        ("force-legal", "custom_check_link_sml_legal_sim_rule",
         "custom_check_link_sml_legal_sim_rule entry returns LEGAL(1)."),
        ("sl-check-force", "sml_sl_Check",
         "sml_sl_Check entry returns pass(1)."),
    )

    for label, sym, why in prologue_targets:
        bounds = find_cati_symbol(blob, sym)
        if not bounds:
            report["errors"].append(f"CATI symbol not uniquely found: {sym}")
            all_ok = False
            continue
        va_s, va_e = bounds
        report["cati_found"][sym] = (hex(va_s), hex(va_e))
        try:
            foff = va_to_file_off(va_s, rom_doff, rom_end)
        except ValueError as exc:
            report["errors"].append(str(exc))
            all_ok = False
            continue
        actual_bytes = trimmed[foff:foff + 4]
        actual_hex = actual_bytes.hex()
        valid_pro, kind = is_valid_micromips_prologue(actual_bytes)
        if not valid_pro:
            all_ok = False
        report["checks"].append({
            "label": label, "offset": hex(foff), "va": hex(va_s),
            "actual": actual_hex, "kind": kind, "matched": valid_pro,
        })
        patches.append({
            "label": label, "offset": hex(foff), "old": actual_hex, "new": "01d2e0db",
            "why": f"{why} CATI VA {va_s:#x}.",
        })

    smu_bounds = find_cati_symbol(blob, "smu_check_sml")
    if not smu_bounds:
        report["errors"].append("CATI symbol not uniquely found: smu_check_sml")
        return False, report, []

    smu_va_s, smu_va_e = smu_bounds
    report["cati_found"]["smu_check_sml"] = (hex(smu_va_s), hex(smu_va_e))
    try:
        smu_off = va_to_file_off(smu_va_s, rom_doff, rom_end)
        smu_end = va_to_file_off(smu_va_e - 1, rom_doff, rom_end) + 1
    except ValueError as exc:
        report["errors"].append(str(exc))
        return False, report, []

    smu_slice = trimmed[smu_off:smu_end]
    gate_hits = scan_smu_gates_bitmask(smu_slice)
    if len(gate_hits) != 6:
        report["errors"].append(
            "Unable to uniquely locate the 6-gate microMIPS32 spine inside smu_check_sml."
        )
        return False, report, []

    for lab, rel_off, old_hex, new_hex, why in gate_hits:
        goff = smu_off + rel_off
        gva = DEFAULT_MD1ROM_BASE_VA + (goff - rom_doff)
        report["checks"].append({
            "label": lab, "offset": hex(goff), "va": hex(gva),
            "actual": old_hex, "kind": "smu-spine-bitmask", "matched": True,
        })
        patches.append({"label": lab, "offset": hex(goff), "old": old_hex, "new": new_hex, "why": why})

    return all_ok and len(patches) == 8, report, patches


# ---------------------------------------------------------------------------
# Patching, CERT2 Signing & Structural/Byte-Exact Auditing
# ---------------------------------------------------------------------------

def apply_patch_table(stock_bytes: bytes, patches: list[dict]) -> tuple[bytes, list[tuple[str, int, bytes, bytes]]]:
    buf = bytearray(stock_bytes)
    table: list[tuple[str, int, bytes, bytes]] = []
    for entry in patches:
        label = entry["label"]
        off = int(entry["offset"], 16) if isinstance(entry["offset"], str) else int(entry["offset"])
        old = bytes.fromhex(entry["old"])
        new = bytes.fromhex(entry["new"])
        if len(old) != len(new):
            raise ValueError(f"Patch '{label}' length mismatch: old={len(old)} new={len(new)}")
        if off + len(old) > len(buf):
            raise ValueError(f"Patch '{label}' offset {off:#x} exceeds image size {len(buf)}")
        actual = bytes(buf[off:off + len(old)])
        if actual != old:
            raise ValueError(
                f"Patch '{label}' at {off:#x}: expected {old.hex()}, found {actual.hex()}. "
                "Wrong firmware or already patched image."
            )
        buf[off:off + len(old)] = new
        table.append((label, off, old, new))
    return bytes(buf), table


def sign_and_audit(
    trimmed: bytes,
    stock_trimmed_path: Path,
    patches: list[dict],
    out_path: Path,
    work_dir: Path,
    profile_id: str,
) -> tuple[bytes, int]:
    work_dir.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    ok_stock, rep_stock = imageaudit.audit_image(stock_trimmed_path)
    if not ok_stock:
        print("ERROR: Stock md1img structural audit failed:", file=sys.stderr)
        print(imageaudit.render(rep_stock), file=sys.stderr)
        return b"", 1

    patched_raw, table = apply_patch_table(trimmed, patches)
    ok_cmp, rep_cmp = imageaudit.compare_built(trimmed, patched_raw, table)
    if not ok_cmp:
        print(f"ERROR: compare_built audit failed: {rep_cmp['unexplained']}", file=sys.stderr)
        return b"", 1

    raw_patched_path = work_dir / f"md1img_{profile_id}_patched.raw.img"
    raw_patched_path.write_bytes(patched_raw)

    sign_cmd = [sys.executable, str(ROOT_DIR / "sign_mtk_cert.py"), "-w", str(raw_patched_path), "-o", str(out_path)]
    sign_res = subprocess.run(sign_cmd, text=True, capture_output=True, timeout=60.0)
    if sign_res.returncode != 0 or not out_path.is_file():
        print(sign_res.stdout)
        print(sign_res.stderr, file=sys.stderr)
        print("ERROR: sign_mtk_cert.py failed.", file=sys.stderr)
        return b"", sign_res.returncode or 1

    ok_out, rep_out = imageaudit.audit_image(out_path)
    print(f"Audit result: {imageaudit.render(rep_out).splitlines()[0]}")
    if not ok_out:
        print("ERROR: Signed md1img audit failed:", file=sys.stderr)
        print(imageaudit.render(rep_out), file=sys.stderr)
        return b"", 1
    return out_path.read_bytes(), 0


# ---------------------------------------------------------------------------
# Multi-Profile Image Resolution for flash / revert
# ---------------------------------------------------------------------------

def resolve_flash_image(
    explicit_image: Path | None,
    explicit_profile: Path | None,
    adb_info: dict[str, str] | None,
    fb_info: dict[str, str] | None,
) -> tuple[Path, dict | None]:
    if explicit_image:
        p = explicit_image.resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Signed image not found: {p}")
        prof = load_profile(explicit_profile.resolve()) if explicit_profile else None
        return p, prof

    if explicit_profile:
        prof = load_profile(explicit_profile.resolve())
        cand = WORK_DIR / f"md1img_{prof['id']}_patched.signed.img"
        if not cand.is_file():
            raise FileNotFoundError(
                f"Signed image for profile '{prof['id']}' not found: {cand}\n"
                f"Build it first: python unlock_modem.py build --profile \"{explicit_profile}\" <stock_md1img>"
            )
        return cand, prof

    # Auto-discover signed images in work/
    candidates = sorted(WORK_DIR.glob("md1img_*_patched.signed.img")) if WORK_DIR.is_dir() else []
    if not candidates:
        raise FileNotFoundError(
            "No patched signed images found in work/. Run 'build' first or pass image path explicitly."
        )
    if len(candidates) == 1:
        # Try matching a profile if one matches its id
        stem_id = re.sub(r"^md1img_(.+)_patched\.signed$", r"\1", candidates[0].stem)
        prof_path = PROFILES_DIR / f"{stem_id}.json"
        prof = load_profile(prof_path) if prof_path.is_file() else None
        return candidates[0], prof

    # Multiple signed images exist -> match connected device to profiles/*.json
    matched_profs = match_profiles_to_device(adb_info, fb_info)
    usable = []
    for _p_path, prof in matched_profs:
        cand = WORK_DIR / f"md1img_{prof['id']}_patched.signed.img"
        if cand.is_file():
            usable.append((cand, prof))
    if len(usable) == 1:
        print(f"Auto-matched signed image for connected device -> profile '{usable[0][1]['id']}'")
        return usable[0]

    listing = "\n  ".join(str(c) for c in candidates)
    raise RuntimeError(
        "Multiple signed images exist in work/ and could not uniquely auto-select one:\n"
        f"  {listing}\n"
        "Pass '--profile profiles/<id>.json' or the exact image path."
    )


def resolve_revert_backup(
    explicit_backup: Path | None,
    explicit_profile: Path | None,
    slot: str,
    adb_info: dict[str, str] | None,
    fb_info: dict[str, str] | None,
) -> Path:
    if explicit_backup:
        p = explicit_backup.resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Backup image not found: {p}")
        return p

    # Gather all stock backups in backups/, preferring trimmed images
    all_backups: list[Path] = []
    if BACKUPS_DIR.is_dir():
        all_backups = sorted(BACKUPS_DIR.glob("*stock_trimmed*.img")) + sorted(
            p for p in BACKUPS_DIR.glob("*stock*.img") if "trimmed" not in p.name
        )
    if not all_backups:
        raise FileNotFoundError("No stock backup images found in backups/. Pass '--backup <path>' explicitly.")

    def find_by_profile(prof: dict) -> Path | None:
        exp_size = int(prof["stock_md1img"]["size"])
        exp_sha = prof["stock_md1img"]["sha256"].lower()
        for b in all_backups:
            raw = b.read_bytes()
            trimmed = trim_to_mkimg_eof(raw, quiet=True)
            if len(trimmed) == exp_size and sha256_bytes(trimmed) == exp_sha:
                return b
        return None

    if explicit_profile:
        prof = load_profile(explicit_profile.resolve())
        found = find_by_profile(prof)
        if not found:
            raise FileNotFoundError(
                f"No backup in backups/ matches profile '{prof['id']}' "
                f"(expected sha256={prof['stock_md1img']['sha256']})."
            )
        return found

    # Try matching connected device to a profile first
    matched_profs = match_profiles_to_device(adb_info, fb_info)
    matched_backups: list[tuple[Path, str]] = []
    for _p_path, prof in matched_profs:
        found = find_by_profile(prof)
        if found:
            matched_backups.append((found, prof["id"]))
    if len(matched_backups) == 1:
        print(f"Auto-matched stock backup for connected device -> profile '{matched_backups[0][1]}'")
        return matched_backups[0][0]

    # Otherwise check if all backups represent a single unique stock image hash
    unique_by_sha: dict[str, Path] = {}
    for b in all_backups:
        try:
            trimmed = trim_to_mkimg_eof(b.read_bytes(), quiet=True)
        except Exception:
            continue
        sha = sha256_bytes(trimmed)
        if sha not in unique_by_sha:
            unique_by_sha[sha] = b

    if len(unique_by_sha) == 1:
        return next(iter(unique_by_sha.values()))

    # Multiple different devices' backups exist -> check exact slot-named trimmed file only if unambiguous
    listing = "\n  ".join(f"{p} (trimmed sha256={sha[:12]}...)" for sha, p in unique_by_sha.items())
    raise RuntimeError(
        "Multiple different stock backups exist in backups/ and could not uniquely auto-select one:\n"
        f"  {listing}\n"
        "Pass '--profile profiles/<id>.json' or '--backup <path>'."
    )


# ---------------------------------------------------------------------------
# CLI Commands: status, dump, check, build, flash, revert, audit
# ---------------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> int:
    adb_info = detect_adb_info()
    if adb_info:
        print("=== Connected via ADB (Android OS) ===")
        for prop in (
            "ro.product.model",
            "ro.product.device",
            "ro.boot.hardware.sku",
            "ro.build.display.id",
            "ro.boot.slot_suffix",
            "gsm.version.baseband",
            "gsm.sim.state",
            "gsm.sim.operator.alpha",
            "vendor.gsm.sim.slot.lock.device.lock.remain.count",
        ):
            res = run_cmd(["adb", "shell", "getprop", prop], timeout=3.0)
            print(f"  {prop:<52}: {res.stdout.strip()}")
        print(f"  Target active modem partition                       : {partition_for_slot(adb_info['slot'])}")
        matched = match_profiles_to_device(adb_info, None)
        if matched:
            print(f"  Matched profile(s)                                  : {', '.join(p.name for p, _ in matched)}")
        return 0

    fb_info = detect_fastboot_info()
    if fb_info:
        print("=== Connected via Fastboot (Bootloader) ===")
        print(f"  current-slot                : {fb_info['slot']}")
        print(f"  securestate                 : {fb_info['securestate']}")
        print(f"  product / sku               : {fb_info['product']} / {fb_info['sku']}")
        print(f"  Target active modem partition: {partition_for_slot(fb_info['slot'])}")
        matched = match_profiles_to_device(None, fb_info)
        if matched:
            print(f"  Matched profile(s)          : {', '.join(p.name for p, _ in matched)}")
        return 0

    print("ERROR: No device detected via ADB or Fastboot.", file=sys.stderr)
    return 1


def cmd_dump(args: argparse.Namespace) -> int:
    adb_info = detect_adb_info()
    slot = resolve_target_slot(args.slot, mode="adb")
    part_name = partition_for_slot(slot)
    dev_tag = re.sub(r"[^A-Za-z0-9_-]", "", (adb_info or {}).get("device", ""))
    prefix = f"{dev_tag}_{part_name}" if dev_tag else part_name

    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    raw_out = (args.output or (BACKUPS_DIR / f"{prefix}_stock.img")).resolve()
    trimmed_out = BACKUPS_DIR / f"{prefix}_stock_trimmed.img"

    print(f"Detected active slot : _{slot} -> dumping /dev/block/by-name/{part_name}")
    remote_tmp = f"/sdcard/{part_name}_stock.img"
    dd_res = run_cmd(
        ["adb", "shell", f"su -c 'dd if=/dev/block/by-name/{part_name} of={remote_tmp} bs=1M'"],
        timeout=120.0,
    )
    if dd_res.returncode != 0:
        print(dd_res.stderr or dd_res.stdout, file=sys.stderr)
        print("ERROR: Root dd dump failed (ensure Magisk/KernelSU root is granted to adb shell).", file=sys.stderr)
        return 1

    pull_res = run_cmd(["adb", "pull", remote_tmp, str(raw_out)], timeout=120.0)
    run_cmd(["adb", "shell", "rm", "-f", remote_tmp], timeout=10.0)
    if pull_res.returncode != 0 or not raw_out.is_file():
        print("ERROR: Failed to pull dumped md1img from device.", file=sys.stderr)
        return 1

    raw = raw_out.read_bytes()
    trimmed = trim_to_mkimg_eof(raw)
    trimmed_out.write_bytes(trimmed)
    ok_aud, rep_aud = imageaudit.audit_image(trimmed_out)
    print(f"Saved raw dump       : {raw_out} ({len(raw)} bytes)")
    print(f"Saved trimmed backup : {trimmed_out} ({len(trimmed)} bytes, sha256={sha256_bytes(trimmed)})")
    print(f"Stock audit          : {imageaudit.render(rep_aud).splitlines()[0]}")
    return 0 if ok_aud else 1


def cmd_check(args: argparse.Namespace) -> int:
    in_path = args.input_md1img.resolve()
    if not in_path.is_file():
        print(f"ERROR: Input file not found: {in_path}", file=sys.stderr)
        return 1

    raw = in_path.read_bytes()
    if not raw:
        print(f"ERROR: Input file is empty: {in_path}", file=sys.stderr)
        return 1

    all_profiles = load_all_profiles()
    raw_sha = sha256_bytes(raw)
    for p_path, prof in all_profiles:
        if raw_sha == prof.get("known_signed_sha256", "").lower():
            print(f"Status: Already signed/patched verified-live image matching profile '{prof['id']}' ({p_path.name}).")
            return 0

    trimmed = trim_to_mkimg_eof(raw)
    trimmed_sha = sha256_bytes(trimmed)

    with tempfile.TemporaryDirectory(prefix="md1_chk_") as tmp:
        tmp_img = Path(tmp) / "trimmed.img"
        tmp_img.write_bytes(trimmed)
        ok_aud, rep_aud = imageaudit.audit_image(tmp_img)

    print(f"Trimmed size  : {len(trimmed)} bytes")
    print(f"Trimmed SHA256: {trimmed_sha}")
    print(f"Stock audit   : {imageaudit.render(rep_aud).splitlines()[0]}")
    if not ok_aud:
        print("ERROR: Stock image failed structural/CERT audit:", file=sys.stderr)
        print(imageaudit.render(rep_aud), file=sys.stderr)
        return 1

    ok_reloc, rep_reloc, patches = relocate_patches_via_cati(trimmed)
    print(f"md1_dbginfo   : {rep_reloc['dbginfo_name']}")
    for sym, bounds in rep_reloc["cati_found"].items():
        print(f"  CATI {sym}: VA [{bounds[0]}, {bounds[1]})")
    for chk in rep_reloc["checks"]:
        mark = "OK" if chk["matched"] else "MISMATCH"
        print(f"  [{mark}] {chk['label']:<15} off={chk['offset']} old={chk['actual']} ({chk['kind']})")
    for err in rep_reloc["errors"]:
        print(f"  [ERROR] {err}")

    matched_prof: tuple[Path, dict] | None = None
    for p_path, prof in all_profiles:
        if len(trimmed) == int(prof["stock_md1img"]["size"]) and trimmed_sha == prof["stock_md1img"]["sha256"].lower():
            matched_prof = (p_path, prof)
            break

    print()
    if matched_prof:
        p_path, prof = matched_prof
        print(f"Result: [TIER 1: VERIFIED PROFILE MATCH] -> {prof['label']} ({p_path.name})")
        print(f"Run   : python unlock_modem.py build --profile \"{p_path}\" \"{args.input_md1img}\"")
        return 0

    if ok_reloc:
        print("Result: [TIER 2/3: STRUCTURAL BITMASK PATTERN MATCH — 8/8 sites uniquely resolved]")
        if args.emit_profile:
            emit_path = args.emit_profile.resolve()
            emit_path.parent.mkdir(parents=True, exist_ok=True)
            new_prof = {
                "schema": 1,
                "id": emit_path.stem,
                "label": f"Auto-generated profile from {rep_reloc['dbginfo_name']}",
                "status": "experimental-auto-relocated",
                "securestate": "flashing_unlocked",
                "stock_md1img": {"size": len(trimmed), "sha256": trimmed_sha},
                "modem_unlock": {"slot": "auto", "patches": patches},
                "verify": {
                    "remain_must_stay": "5",
                    "ee_must_stay": "0",
                    "sim_state_unlocked": "LOADED",
                    "sim_state_locked": "NETWORK_LOCKED",
                },
            }
            emit_path.write_text(json.dumps(new_prof, indent=2) + "\n", encoding="utf-8")
            print(f"Emitted profile: {emit_path}")
            print(f"Build command  : python unlock_modem.py build --profile \"{emit_path}\" \"{args.input_md1img}\"")
        else:
            print(f"Test build: python unlock_modem.py build --experimental-relocate \"{args.input_md1img}\"")
        return 0

    print("Result: [TIER 4: INCOMPATIBLE] CATI symbols or smu_check_sml spine differ; manual analysis required.")
    return 1


def cmd_build(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile.resolve())
    in_path = args.input_md1img.resolve()
    if not in_path.is_file():
        print(f"ERROR: Input file not found: {in_path}", file=sys.stderr)
        return 1

    raw = in_path.read_bytes()
    if not raw:
        print(f"ERROR: Input file is empty: {in_path}", file=sys.stderr)
        return 1

    known_signed = profile.get("known_signed_sha256", "").lower()
    if known_signed and sha256_bytes(raw) == known_signed:
        print(f"ERROR: Input is already the signed patched {profile['id']} md1img image.", file=sys.stderr)
        return 1

    trimmed = trim_to_mkimg_eof(raw)
    trimmed_sha = sha256_bytes(trimmed)
    exp_size = int(profile["stock_md1img"]["size"])
    exp_sha = profile["stock_md1img"]["sha256"].lower()
    exact_stock = (len(trimmed) == exp_size and trimmed_sha == exp_sha)

    if not exact_stock and not args.experimental_relocate:
        print(
            f"ERROR: Trimmed stock md1img does not match profile '{profile['id']}' ({profile['label']}).\n"
            f"  Expected: {exp_size} bytes, sha256={exp_sha}\n"
            f"  Got     : {len(trimmed)} bytes, sha256={trimmed_sha}\n"
            f"  Tip     : Run 'python unlock_modem.py check \"{args.input_md1img}\"' or use '--experimental-relocate'.",
            file=sys.stderr,
        )
        return 1

    patches = profile["modem_unlock"]["patches"]
    experimental = False
    if not exact_stock and args.experimental_relocate:
        ok_reloc, rep_reloc, patches = relocate_patches_via_cati(trimmed)
        print(f"EXPERIMENTAL RELOCATE: dbginfo={rep_reloc['dbginfo_name']}")
        if not ok_reloc:
            for err in rep_reloc["errors"]:
                print(f"ERROR: {err}", file=sys.stderr)
            return 1
        experimental = True

    profile_id = "experimental" if experimental else profile["id"]
    default_out = WORK_DIR / f"md1img_{profile_id}_patched.signed.img"
    out_path = (args.output or default_out).resolve()
    work_dir = (args.work_dir or (out_path.parent / "modem_work")).resolve()

    stock_trimmed_path = find_existing_stock_trimmed(len(trimmed), trimmed_sha)
    if stock_trimmed_path:
        print(f"Reusing existing stock trimmed backup: {stock_trimmed_path}")
    else:
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        stock_trimmed_path = BACKUPS_DIR / f"md1img_{profile_id}_stock_trimmed.img"
        stock_trimmed_path.write_bytes(trimmed)
        print(f"Saved stock trimmed backup: {stock_trimmed_path}")

    out_bytes, rc = sign_and_audit(trimmed, stock_trimmed_path, patches, out_path, work_dir, profile_id)
    if rc != 0:
        return rc

    out_sha = sha256_bytes(out_bytes)
    active_slot = detect_slot_adb() or detect_slot_fastboot()
    target_part = partition_for_slot(active_slot) if active_slot else "md1img_<a|b>"

    print()
    print(f"Patched signed modem ready : {out_path}")
    print(f"Intermediate raw patched   : {work_dir / f'md1img_{profile_id}_patched.raw.img'}")
    print(f"Stock revert image         : {stock_trimmed_path}")
    print(f"Size                       : {len(out_bytes)} bytes")
    print(f"SHA256                     : {out_sha}")
    if known_signed and out_sha == known_signed:
        print(f"Verified                   : Exact match to verified-live {profile['label']}")
    elif experimental:
        print("WARNING                    : EXPERIMENTAL BUILD — keep stock backup and verify revert works!")

    print()
    print("Next steps (dynamic active-slot flash):")
    prof_flag = f"--profile \"{args.profile}\" " if not experimental else ""
    print(f"  Auto-flash : python unlock_modem.py flash {prof_flag}--reboot")
    print(f"  Auto-revert: python unlock_modem.py revert {prof_flag}--reboot")
    print(f"  Manual     : fastboot flash {target_part} \"{out_path}\"")
    return 0


def cmd_flash(args: argparse.Namespace) -> int:
    adb_info = detect_adb_info()
    fb_info = detect_fastboot_info()

    img_path, prof = resolve_flash_image(args.signed_image, args.profile, adb_info, fb_info)
    print(f"Selected signed image: {img_path}")

    ok_aud, rep_aud = imageaudit.audit_image(img_path)
    if not ok_aud:
        print("ERROR: Refusing to flash — target image failed structural/CERT2 audit:", file=sys.stderr)
        print(imageaudit.render(rep_aud), file=sys.stderr)
        return 1

    # Ensure a valid revert backup exists (matching the profile if known)
    if prof:
        exp_size = int(prof["stock_md1img"]["size"])
        exp_sha = prof["stock_md1img"]["sha256"].lower()
        if not find_existing_stock_trimmed(exp_size, exp_sha):
            # Check raw backups too before refusing
            has_raw_match = any(
                sha256_bytes(trim_to_mkimg_eof(p.read_bytes(), quiet=True)) == exp_sha
                for p in (BACKUPS_DIR.glob("*stock*.img") if BACKUPS_DIR.is_dir() else [])
            )
            if not has_raw_match:
                print(
                    f"ERROR: Refusing to flash — no stock backup in backups/ matches profile '{prof['id']}'.",
                    file=sys.stderr,
                )
                return 1
    else:
        has_any_backup = BACKUPS_DIR.is_dir() and any(BACKUPS_DIR.glob("*stock*.img"))
        if not has_any_backup:
            print("ERROR: Refusing to flash — no stock backup found in backups/.", file=sys.stderr)
            return 1

    if adb_info and not fb_info:
        print("Rebooting device from ADB into bootloader...")
        run_cmd(["adb", "reboot", "bootloader"], timeout=10.0)
        fb_info = wait_for_fastboot(timeout=30.0)

    slot = resolve_target_slot(args.slot, mode="fastboot")
    fb_info = fb_info or detect_fastboot_info()
    sec = fb_info.get("securestate") if fb_info else ""
    if sec != "flashing_unlocked":
        print(f"ERROR: Bootloader securestate is '{sec}' (must be 'flashing_unlocked').", file=sys.stderr)
        return 1

    part = partition_for_slot(slot)
    inactive_part = partition_for_slot("b" if slot == "a" else "a")
    print(f"Active slot detected : {slot}")
    print(f"Flashing partition   : {part} (leaving inactive {inactive_part} untouched as backup)")

    res = subprocess.run(["fastboot", "flash", part, str(img_path)], timeout=120.0)
    if res.returncode != 0:
        print(f"ERROR: fastboot flash {part} failed.", file=sys.stderr)
        return res.returncode

    if args.reboot:
        subprocess.run(["fastboot", "reboot"], timeout=15.0)
    return 0


def cmd_revert(args: argparse.Namespace) -> int:
    adb_info = detect_adb_info()
    fb_info = detect_fastboot_info()

    if adb_info and not fb_info:
        print("Rebooting device from ADB into bootloader...")
        run_cmd(["adb", "reboot", "bootloader"], timeout=10.0)
        fb_info = wait_for_fastboot(timeout=30.0)

    slot = resolve_target_slot(args.slot, mode="fastboot")
    part = partition_for_slot(slot)
    stock_path = resolve_revert_backup(args.backup_image, args.profile, slot, adb_info, fb_info)

    raw = stock_path.read_bytes()
    trimmed = trim_to_mkimg_eof(raw, quiet=True)
    if len(trimmed) == len(raw):
        ok_aud, rep_aud = imageaudit.audit_image(stock_path)
        if not ok_aud:
            print("ERROR: Stock backup failed integrity audit; refusing to flash:", file=sys.stderr)
            print(imageaudit.render(rep_aud), file=sys.stderr)
            return 1
        print(f"Reverting active slot '{slot}' ({part}) using verified stock image: {stock_path}")
        res = subprocess.run(["fastboot", "flash", part, str(stock_path)], timeout=120.0)
        if res.returncode != 0:
            return res.returncode
    else:
        with tempfile.TemporaryDirectory(prefix="md1_rev_") as tmp:
            tmp_img = Path(tmp) / "revert_trimmed.img"
            tmp_img.write_bytes(trimmed)
            ok_aud, rep_aud = imageaudit.audit_image(tmp_img)
            if not ok_aud:
                print("ERROR: Stock backup failed integrity audit; refusing to flash:", file=sys.stderr)
                print(imageaudit.render(rep_aud), file=sys.stderr)
                return 1
            print(f"Reverting active slot '{slot}' ({part}) using trimmed backup from: {stock_path}")
            res = subprocess.run(["fastboot", "flash", part, str(tmp_img)], timeout=120.0)
            if res.returncode != 0:
                return res.returncode

    if args.reboot:
        subprocess.run(["fastboot", "reboot"], timeout=15.0)
    print(f"Revert complete on {part}.")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    target = args.image.resolve()
    if not target.is_file():
        print(f"ERROR: File not found: {target}", file=sys.stderr)
        return 1
    ok, rep = imageaudit.audit_image(target)
    print(imageaudit.render(rep))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="cancunn-freedom: Check, dump, build, audit, dynamically flash, and revert MTK md1img."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show active slot (a/b), baseband, and SIM lock status via ADB/Fastboot.")

    p_dump = sub.add_parser("dump", help="Auto-detect active slot (_a/_b) via ADB root, dump stock md1img, and audit.")
    p_dump.add_argument("--slot", choices=["a", "b"], default=None, help="Override slot to dump (default: auto)")
    p_dump.add_argument("-o", "--output", type=Path, default=None, help="Output raw dump path")

    p_check = sub.add_parser("check", help="Check md1img compatibility and auto-locate 8 patch sites via CATI/bitmask.")
    p_check.add_argument("input_md1img", type=Path, help="Path to stock md1img.img")
    p_check.add_argument("--emit-profile", type=Path, default=None,
                         help="Emit auto-relocated JSON profile to this path if 8/8 structural match succeeds")

    p_build = sub.add_parser("build", help="Trim, patch, CERT2-sign, and audit md1img.")
    p_build.add_argument("input_md1img", type=Path, help="Path to stock md1img.img")
    p_build.add_argument("-o", "--output", type=Path, default=None, help="Output signed image path")
    p_build.add_argument("--work-dir", type=Path, default=None, help="Intermediate working directory")
    p_build.add_argument("--profile", type=Path, default=DEFAULT_PROFILE,
                         help=f"Device profile JSON (default: {DEFAULT_PROFILE})")
    p_build.add_argument("--experimental-relocate", action="store_true",
                         help="Build using dynamic CATI + bitmask spine relocation if input differs from profile")

    p_flash = sub.add_parser("flash", help="Dynamically detect active slot (a/b) in fastboot and flash signed md1img.")
    p_flash.add_argument("signed_image", type=Path, nargs="?", default=None,
                         help="Path to patched signed md1img (optional if --profile or single work image)")
    p_flash.add_argument("--profile", type=Path, default=None,
                         help="Select signed image and verify backup using this profile JSON")
    p_flash.add_argument("--slot", choices=["a", "b"], default=None, help="Override target slot (default: auto-detect)")
    p_flash.add_argument("--reboot", action="store_true", help="Reboot device automatically after flashing")

    p_rev = sub.add_parser("revert", help="Dynamically detect active slot (a/b) and restore verified stock md1img.")
    p_rev.add_argument("--backup", dest="backup_image", type=Path, default=None,
                       help="Explicit path to stock md1img backup")
    p_rev.add_argument("--profile", type=Path, default=None,
                       help="Select stock backup in backups/ matching this profile's SHA-256")
    p_rev.add_argument("--slot", choices=["a", "b"], default=None, help="Override target slot (default: auto-detect)")
    p_rev.add_argument("--reboot", action="store_true", help="Reboot device automatically after reverting")

    p_audit = sub.add_parser("audit", help="Run structural + CERT2 digest audit on an md1img file.")
    p_audit.add_argument("image", type=Path, help="Path to md1img image")

    args = parser.parse_args()
    try:
        if args.cmd == "status":
            return cmd_status(args)
        if args.cmd == "dump":
            return cmd_dump(args)
        if args.cmd == "check":
            return cmd_check(args)
        if args.cmd == "build":
            return cmd_build(args)
        if args.cmd == "flash":
            return cmd_flash(args)
        if args.cmd == "revert":
            return cmd_revert(args)
        if args.cmd == "audit":
            return cmd_audit(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())