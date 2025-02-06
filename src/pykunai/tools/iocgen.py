import sys
import json
import uuid
import argparse


def bound_severity(s: int) -> int:
    if s < 0:
        return 0
    if s > 10:
        return 10
    return s


def main() -> None:
    parser = argparse.ArgumentParser(description="Help creating iocs from batch")
    parser.add_argument("source", type=str, help="IoC source")
    parser.add_argument("value", type=str, help="IoC value")
    parser.add_argument("severity", type=int, help="IoC value")

    args = parser.parse_args()

    if len(args.value) == 0:
        sys.exit(0)

    print(
        json.dumps(
            {
                "uuid": str(uuid.uuid4()),
                "source": args.source,
                "value": args.value,
                "severity": bound_severity(args.severity),
            }
        )
    )


if __name__ == "__main__":
    main()
