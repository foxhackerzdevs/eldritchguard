#!/usr/bin/env python3
import subprocess
import sys

BINARY = "../target/debug/eldritchguard"

def load_payloads():
    result = []
    with open("test_payloads.py") as f:
        content = f.read()
    ns = {}
    exec(content.split("if __name__")[0], ns)
    return ns["PAYLOADS"]

def run_one(text):
    proc = subprocess.run(
        [BINARY], input=text + "\n", capture_output=True, text=True, timeout=5
    )
    breached = "CONTAINMENT BREACH" in proc.stderr
    return breached

def main():
    payloads = load_payloads()
    results = []
    for text, label, category in payloads:
        breached = run_one(text)
        results.append((text, label, category, breached))

    print(f"{'CATEGORY':22s} {'LABEL':28s} {'FLAGGED':8s} {'TEXT':60s}")
    print("-" * 120)
    for text, label, category, breached in results:
        display_text = (text[:57] + "...") if len(text) > 60 else text
        print(f"{category:22s} {label:28s} {str(breached):8s} {display_text:60s}")

    print()
    print("=" * 60)
    print("SUMMARY BY CATEGORY")
    print("=" * 60)

    categories = {}
    for text, label, category, breached in results:
        categories.setdefault(category, []).append((label, breached))

    total_fp = 0
    total_fn = 0
    for cat, items in categories.items():
        flagged = sum(1 for _, b in items if b)
        n = len(items)
        print(f"\n{cat} (n={n}):")
        print(f"  flagged: {flagged}/{n}")
        for label, breached in items:
            if label == "benign" and breached:
                total_fp += 1
            if label == "malicious" and not breached:
                total_fn += 1

    print()
    print("=" * 60)
    print(f"TOTAL FALSE POSITIVES (benign flagged as breach): {total_fp}")
    print(f"TOTAL FALSE NEGATIVES (malicious NOT flagged):     {total_fn}")
    print("=" * 60)

if __name__ == "__main__":
    main()
