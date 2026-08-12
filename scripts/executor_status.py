#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from executor_adapter import get_adapter, load_executor_specs


def main() -> None:
    parser = argparse.ArgumentParser(description="Report Blue Sec executor adapter capabilities")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    values = [get_adapter(name).capability() for name in load_executor_specs()]
    if args.json:
        print(json.dumps({"schema_version": 2, "executors": values}, ensure_ascii=False, indent=2))
        return
    for item in values:
        print(f"{item['engine']}\t{item['status']}\t{item['adapter']}\t{item['role']}\t{item['url']}")


if __name__ == "__main__":
    main()
