"""
Initialize the SQLite database from the synthetic datasets.

Usage (from the project root):
    python -m scripts.init_database
    python -m scripts.init_database --db custom/path.db

Idempotent: rebuilds the database from the CSVs, runs the alert engine,
builds investigation timelines, seeds analyst notes, awareness modules and
synthetic quiz results.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

import config  # noqa: E402
from database import init_database  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=None,
                        help="Database path (default: backend/threat_intel.db)")
    args = parser.parse_args()

    if not config.THREAT_DATASET_CSV.exists():
        print("Synthetic dataset missing. Generating it first ...")
        import subprocess
        subprocess.run([sys.executable,
                        str(PROJECT_ROOT / "data" / "generate_threat_data.py")],
                       check=True)

    summary = init_database(db_path=args.db)
    print("Database initialized:", config.DATABASE_PATH
          if args.db is None else args.db)
    for key, value in summary.items():
        print(f"  {key:20} {value}")
    print("\nAll data is SYNTHETIC / DEMO ONLY (defensive education).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
