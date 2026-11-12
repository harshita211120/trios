"""
Combined defense-in-depth test: validate -> taint -> budget.

Run from host_agent/ with the RISC-V xv6 tree built:
    XV6_DIR=../xv6-riscv python3 test_combined.py

Groups used in the guest:
  group 1: generous budget, used for benign tool calls
  group 2: tight budget, used for the injected-follow-through attack
"""
import os
import re
import sys

from qemu_bridge import QEMUBridge
from tools import validate_action, ValidationError
from match_action_agent import MatchActionPlanner

XV6_DIR = os.environ.get("XV6_DIR", "../xv6-riscv")
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    tail = f" -- {detail}" if detail else ""
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{tail}")


def stat(bridge, gid):
    out = bridge.send_command(f"budgetstat {gid}")
    m = re.search(
        r"group (\d+): budget (-?\d+)/(\d+).*?allowed (\d+) blocked (\d+) "
        r"refused (\d+) tainted (\d)", out)
    if not m:
        print(f"  (could not parse budgetstat output: {out!r})")
        return None
    g, budget, mx, allowed, blocked, refused, tainted = map(int, m.groups())
    return {"budget": budget, "max": mx, "allowed": allowed,
            "blocked": blocked, "refused": refused, "tainted": tainted,
            "raw": m.group(0)}


def main():
    bridge = QEMUBridge(xv6_dir=XV6_DIR)
    try:
        print("\n--- Setup: configure budgeted groups ---")
        bridge.send_command("budgetset 1 500 50 fail")
        bridge.send_command("budgetset 2 50 10 fail")

        print("\n--- Layer 1: host validator ---")
        planner = MatchActionPlanner()
        action = planner.lookup("delete /important.txt")
        try:
            validate_action(action)
            blocked = False
        except ValidationError as e:
            blocked = True
            print(f"  validator said: {e}")
        check("Layer 1: injected delete_file blocked on host", blocked)

        print("\n--- Benign tool call in group 1 ---")
        out = bridge.send_command("agentrun 1 cat report.txt")
        check("trusted read works inside budgeted group", "100 requests" in out)
        s1 = stat(bridge, 1)
        check("call was charged to group 1 and group is clean",
              s1 is not None and s1["allowed"] >= 1 and s1["tainted"] == 0,
              s1["raw"] if s1 else "")

        print("\n--- Untrusted read in group 2 (taint) ---")
        out = bridge.send_command("agentrun 2 cat inbox.txt")
        check("kernel logs taint on inbox.txt", "[KERNEL TAINT]" in out)
        s2 = stat(bridge, 2)
        check("group 2 is flagged tainted",
              s2 is not None and s2["tainted"] == 1, s2["raw"] if s2 else "")

        print("\n--- Layer 3: clean process in tainted group tries rm ---")
        bridge.send_command("agentrun 2 rm important.txt")
        out = bridge.send_command("cat important.txt")
        check("important.txt survives (budget refused the unlink)",
              "CRITICAL" in out)
        s2 = stat(bridge, 2)
        check("group 2 recorded a refused call",
              s2 is not None and s2["refused"] >= 1, s2["raw"] if s2 else "")

        print("\n--- Layer 2: tainted process tries unlink ---")
        out = bridge.send_command("tainttest")
        check("kernel logs denial", "[KERNEL DENIAL]" in out)
        check("tainttest reports success", "[SUCCESS]" in out)
        out = bridge.send_command("cat important.txt")
        check("important.txt still intact", "CRITICAL" in out)

        print("\n--- Kernel-side combined test ---")
        out = bridge.send_command("combotest", timeout=60)
        print(out)
        check("combotest ALL PASSED", "combotest: ALL PASSED" in out)
    finally:
        bridge.close()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n=== {passed}/{len(results)} checks passed ===")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
