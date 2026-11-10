import argparse
import json
import statistics
import time
from collections import Counter
from pathlib import Path

from app.detector import scan

DATASET = Path(__file__).parent / "dataset.json"
TIMING_RUNS = 20

# Fake secrets are assembled here so the JSON file holds no token-shaped strings.
PLACEHOLDERS = {
    "{{AWS_KEY}}": "AKIAIOSFODNN7EXAMPLE",
    "{{AWS_TEMP_KEY}}": "ASIA" + "IOSFODNN7EXAMPLE",
    "{{AWS_SECRET}}": "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "{{GH_TOKEN}}": "ghp_" + "R7kP2mXq9LdT4vB8nZc1" + "Hs6WjY3aEu5Fg0Ko",
    "{{GH_PAT}}": "github_pat_"
    + "11ABCDEFG0123456789_"
    + "abcdefghijklmnopqrstuvwxyz0123456789",
    "{{OPENAI_KEY}}": "sk-" + "Tq8xLm2Vn7Rb4Zc9" + "Yd3Kp6Wf1Hs5JgA0",
    "{{PRIVATE_KEY_HEADER}}": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "{{JWT}}": (
        "eyJhbGciOiJIUzI1NiIs"
        "InR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJkZW1vIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "demo_signature_not_a_real_credential"
    ),
    "{{SLACK_TOKEN}}": (
        "xoxb-" + "000000000000-" + "0000000000000-" + "DemoOnlyNotARealToken1234"
    ),
    "{{STRIPE_KEY}}": ("sk_live_" + "DemoOnlyNotAReal" + "Credential123456789"),
}


def expand(text: str) -> str:
    for placeholder, value in PLACEHOLDERS.items():
        text = text.replace(placeholder, value)
    return text


def ratio(numerator: int, denominator: int) -> str:
    return f"{numerator / denominator:.0%}" if denominator else "n/a"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DATASET,
        help="Path to the evaluation dataset",
    )
    args = parser.parse_args()
    cases = json.loads(args.dataset.read_text(encoding="utf-8"))

    tp, fp, fn = Counter(), Counter(), Counter()
    failures = []
    timings_ms = []

    for case in cases:
        text = expand(case["text"])
        expected = Counter(case["expected"])
        detected = Counter(f.type for f in scan(text))

        for rule, n in (expected & detected).items():
            tp[rule] += n
        for rule, n in (detected - expected).items():
            fp[rule] += n
        for rule, n in (expected - detected).items():
            fn[rule] += n
        if expected != detected:
            failures.append(
                (case["text"], sorted(expected.elements()), sorted(detected.elements()))
            )

        scan(text)  # warm-up
        for _ in range(TIMING_RUNS):
            start = time.perf_counter()
            scan(text)
            timings_ms.append((time.perf_counter() - start) * 1000)

    print(f"{'rule':22} {'precision':>10} {'recall':>8}   TP  FP  FN")
    for rule in sorted(set(tp) | set(fp) | set(fn)):
        print(
            f"{rule:22} {ratio(tp[rule], tp[rule] + fp[rule]):>10} "
            f"{ratio(tp[rule], tp[rule] + fn[rule]):>8}  {tp[rule]:3} {fp[rule]:3} {fn[rule]:3}"
        )

    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    print(f"\nOVERALL precision {ratio(T, T + F)}, recall {ratio(T, T + N)}")
    print(f"Prompts: {len(cases)}, fully correct: {len(cases) - len(failures)}")

    timings_ms.sort()
    print(
        f"\nLatency per scan: mean {statistics.mean(timings_ms):.3f} ms, "
        f"p95 {timings_ms[int(len(timings_ms) * 0.95)]:.3f} ms, max {timings_ms[-1]:.3f} ms"
    )

    long_text = (
        "Here is my log output and some notes about the build. " * 200
    ) + "key=AKIAIOSFODNN7EXAMPLE"
    start = time.perf_counter()
    for _ in range(20):
        scan(long_text)
    per_scan = (time.perf_counter() - start) / 20 * 1000
    print(f"Long prompt ({len(long_text):,} chars): {per_scan:.2f} ms per scan")

    if failures:
        print("\nMISTAKES")
        for text, expected, got in failures:
            print(f"- {text!r}\n    expected {expected}, got {got}")


if __name__ == "__main__":
    main()
