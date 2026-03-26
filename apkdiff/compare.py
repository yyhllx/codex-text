from __future__ import annotations

import argparse

import hashlib


import hashlib


import json
import re
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from androguard.core.apk import APK
from androguard.core.dex import DEX

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+")


@dataclass
class MethodSignature:
    class_name: str
    method_name: str
    parameter_types: List[str]
    return_type: str

    @property
    def key(self) -> str:
        params = ",".join(self.parameter_types)
        return f"{self.class_name}->{self.method_name}({params})"


@dataclass
class ApkSnapshot:
    file_name: str
    sha256: str
    package_name: str
    version_name: str
    version_code: str
    sdk_min: str
    sdk_target: str
    permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]
    native_libs: List[str]
    files: List[str]
    classes: List[str]
    method_signatures: Dict[str, str]
    string_urls: List[str]


def _descriptor_to_type(desc: str) -> str:
    primitives = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    array_depth = desc.count("[")
    clean = desc[array_depth:]

    if clean in primitives:
        base = primitives[clean]
    elif clean.startswith("L") and clean.endswith(";"):
        base = clean[1:-1].replace("/", ".")
    else:
        base = clean

    return base + "[]" * array_depth


def parse_method_descriptor(descriptor: str) -> Tuple[List[str], str]:
    # Example: (Ljava/lang/String;I)Z
    if not descriptor.startswith("("):
        return [], _descriptor_to_type(descriptor)

    params_blob, return_blob = descriptor[1:].split(")")
    params: List[str] = []
    i = 0
    while i < len(params_blob):
        start = i
        while i < len(params_blob) and params_blob[i] == "[":
            i += 1
        if i < len(params_blob) and params_blob[i] == "L":
            i = params_blob.index(";", i) + 1
            params.append(_descriptor_to_type(params_blob[start:i]))
        else:
            i += 1
            params.append(_descriptor_to_type(params_blob[start:i]))

    return params, _descriptor_to_type(return_blob)


def _collect_urls(strings: Iterable[str]) -> List[str]:
    found: List[str] = []
    for s in strings:
        found.extend(URL_PATTERN.findall(s))
    return sorted(set(found))





def normalize_class_name(raw_name: str) -> str:
    if raw_name.startswith("L") and raw_name.endswith(";"):
        return raw_name[1:-1].replace("/", ".")
    return raw_name.replace("/", ".")





def build_snapshot(apk_path: Path) -> ApkSnapshot:
    apk = APK(str(apk_path))

    with zipfile.ZipFile(apk_path, "r") as zf:
        file_list = sorted(zf.namelist())

    class_names: set[str] = set()
    method_sigs: Dict[str, str] = {}
    all_strings: List[str] = []

    for dex_bytes in apk.get_all_dex():
        dex = DEX(dex_bytes)
        for cls in dex.get_classes():
            class_name = normalize_class_name(cls.get_name())



            class_name = cls.get_name().strip("L;").replace("/", ".")


            class_names.add(class_name)
            for method in cls.get_methods():
                params, ret = parse_method_descriptor(method.get_descriptor())
                signature = MethodSignature(
                    class_name=class_name,
                    method_name=method.get_name(),
                    parameter_types=params,
                    return_type=ret,
                )
                method_sigs[signature.key] = signature.return_type
        all_strings.extend(dex.get_strings())

    return ApkSnapshot(
        file_name=apk_path.name,

        sha256=hashlib.sha256(apk_path.read_bytes()).hexdigest(),


        sha256=hashlib.sha256(apk_path.read_bytes()).hexdigest(),

        sha256=apk.get_file_hash(),

        package_name=apk.get_package() or "",
        version_name=apk.get_androidversion_name() or "",
        version_code=str(apk.get_androidversion_code() or ""),
        sdk_min=str(apk.get_min_sdk_version() or ""),
        sdk_target=str(apk.get_target_sdk_version() or ""),
        permissions=sorted(apk.get_permissions()),
        activities=sorted(apk.get_activities()),
        services=sorted(apk.get_services()),
        receivers=sorted(apk.get_receivers()),
        providers=sorted(apk.get_providers()),
        native_libs=sorted([f for f in file_list if f.startswith("lib/") and f.endswith(".so")]),
        files=file_list,
        classes=sorted(class_names),
        method_signatures=method_sigs,
        string_urls=_collect_urls(all_strings),
    )


def compare_lists(before: Sequence[str], after: Sequence[str], limit: int = 100) -> Dict[str, List[str]]:
    before_set = set(before)
    after_set = set(after)
    return {
        "before_only": sorted(before_set - after_set)[:limit],
        "after_only": sorted(after_set - before_set)[:limit],
        "both": sorted(before_set & after_set)[:limit],
    }


def compare_methods(
    before: Dict[str, str], after: Dict[str, str], limit: int = 200
) -> Dict[str, object]:
    before_keys = set(before)
    after_keys = set(after)
    changed_return = []
    for key in sorted(before_keys & after_keys):
        if before[key] != after[key]:
            changed_return.append(
                {
                    "method": key,
                    "before_return": before[key],
                    "after_return": after[key],
                }
            )

    return {
        "before_only_methods": sorted(before_keys - after_keys)[:limit],
        "after_only_methods": sorted(after_keys - before_keys)[:limit],
        "return_type_changed": changed_return[:limit],
    }


def _count_package(classes: Sequence[str], depth: int = 3) -> Dict[str, int]:
    counter = Counter()
    for cls in classes:
        parts = cls.split(".")
        prefix = ".".join(parts[:depth])
        counter[prefix] += 1
    return dict(counter)


def build_report(before_apk: Path, after_apk: Path) -> Dict[str, object]:
    before = build_snapshot(before_apk)
    after = build_snapshot(after_apk)

    report = {
        "inputs": {"before": asdict(before), "after": asdict(after)},
        "summary": {
            "package_changed": {
                "before": before.package_name,
                "after": after.package_name,
            },
            "version_name": {"before": before.version_name, "after": after.version_name},
            "version_code": {"before": before.version_code, "after": after.version_code},
            "sdk_min": {"before": before.sdk_min, "after": after.sdk_min},
            "sdk_target": {"before": before.sdk_target, "after": after.sdk_target},
            "file_count": {"before": len(before.files), "after": len(after.files)},
            "class_count": {"before": len(before.classes), "after": len(after.classes)},
            "method_count": {
                "before": len(before.method_signatures),
                "after": len(after.method_signatures),
            },
        },
        "manifest_diff": {
            "permissions": compare_lists(before.permissions, after.permissions),
            "activities": compare_lists(before.activities, after.activities),
            "services": compare_lists(before.services, after.services),
            "receivers": compare_lists(before.receivers, after.receivers),
            "providers": compare_lists(before.providers, after.providers),
        },
        "resource_diff": {
            "native_libs": compare_lists(before.native_libs, after.native_libs),
            "files": compare_lists(before.files, after.files),
        },
        "dex_diff": {
            "classes": compare_lists(before.classes, after.classes),
            "methods": compare_methods(before.method_signatures, after.method_signatures),
            "package_distribution": {
                "before": _count_package(before.classes),
                "after": _count_package(after.classes),
            },
        },
        "protocol_api_signals": {
            "url_strings": compare_lists(before.string_urls, after.string_urls),
        },
    }
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two full APK files and output structured differences."
    )
    parser.add_argument("before_apk", type=Path, help="Path to baseline APK")
    parser.add_argument("after_apk", type=Path, help="Path to new APK")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("apk_diff_report.json"),
        help="Path to write JSON report",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(args.before_apk, args.after_apk)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Comparison complete: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
