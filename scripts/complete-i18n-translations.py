#!/usr/bin/env python3
"""
补全 i18n locale 文件中的缺失键。
以参考 locale（zh-CN）为基准，用 en-US 作为占位翻译补全其他 locale 的缺失键。
"""

import json
import sys
from pathlib import Path


def load_json(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Failed to load {path}: {e}", file=sys.stderr)
        return None


def complete_locale(
    locales_dir: Path,
    reference: str = "zh-CN",
    fallback: str = "en-US",
) -> int:
    """补全指定目录下的 locale 文件，返回补全的键总数"""
    ref_path = locales_dir / f"{reference}.json"
    fallback_path = locales_dir / f"{fallback}.json"

    if not ref_path.exists():
        print(f"Error: Reference {reference} not found at {ref_path}", file=sys.stderr)
        return 0

    ref_data = load_json(ref_path)
    if ref_data is None:
        return 0

    fallback_data = load_json(fallback_path) if fallback_path.exists() else ref_data

    # 扁平 JSON，键即 key
    ref_keys = set(ref_data.keys())
    locale_files = sorted(locales_dir.glob("*.json"))
    total_added = 0

    for fp in locale_files:
        locale_name = fp.stem
        # 参考 locale 不补全；fallback 用 reference 补全
        if locale_name == reference:
            continue

        data = load_json(fp)
        if data is None:
            continue

        have_keys = set(data.keys())
        missing = ref_keys - have_keys

        if not missing:
            print(f"  {locale_name}: 已完整")
            continue

        # fallback 自身缺失时用 reference 补全
        source_data = fallback_data if locale_name != fallback else ref_data

        added = 0
        for key in sorted(missing):
            val = source_data.get(key) or ref_data.get(key)
            if val is not None:
                data[key] = val
                added += 1

        if added > 0:
            # 按参考 locale 的 key 顺序重排
            ordered = {}
            for k in ref_data.keys():
                ordered[k] = data.get(k, source_data.get(k, ref_data[k]))
            for k in data.keys():
                if k not in ordered:
                    ordered[k] = data[k]

            with open(fp, "w", encoding="utf-8") as f:
                json.dump(ordered, f, ensure_ascii=False, indent=2)

            print(f"  {locale_name}: 补全 {added} 个键")
            total_added += added

    return total_added


def main():
    project_root = Path(__file__).resolve().parent.parent

    dirs_to_complete = [
        ("i18n", "zh-CN", "en-US"),
        ("internal/assets/i18n", "zh-CN", "en-US"),
    ]

    print("补全翻译...\n")
    grand_total = 0

    for rel_dir, ref, fallback in dirs_to_complete:
        locales_dir = project_root / rel_dir
        if not locales_dir.is_dir():
            print(f"跳过 {rel_dir}（目录不存在）")
            continue

        print(f"📁 {rel_dir} (参考: {ref}, 占位: {fallback})")
        added = complete_locale(locales_dir, ref, fallback)
        grand_total += added
        print()

    if grand_total > 0:
        print(f"✅ 共补全 {grand_total} 个翻译键")
    else:
        print("✅ 所有 locale 已完整，无需补全")


if __name__ == "__main__":
    main()
