from qemu_bridge import QEMUBridge
from tools import ToolDispatcher
from match_action_agent import MatchActionPlanner, MatchActionAgent

def test_match_action_pipeline():
    print("=== Match-Action Table Switch Integration Test ===")

    # Start QEMU serial bridge[cite: 2, 3]
    bridge = QEMUBridge(xv6_dir="../xv6-public")

    try:
        dispatcher = ToolDispatcher(bridge=bridge)
        planner = MatchActionPlanner()
        agent = MatchActionAgent(tools=dispatcher, planner=planner)

        # Test Case 1: Exact Match Rule ('list')
        res1 = agent.run("list")
        print(f"Result:\n{res1}")

        # Test Case 2: Regex Field Extraction Match Rule ('read README')[cite: 3, 4]
        res2 = agent.run("read README")
        print(f"Result:\n{res2}")

        # Test Case 3: Table Miss (Unmatched request pattern)[cite: 3]
        res3 = agent.run("what is the weather today?")
        print(f"Result:\n{res3}")

        # Test Case 4: Flow Rule matched disallowed tool (Blocked by Host Validator)[cite: 2, 4]
        res4 = agent.run("delete /important.txt")
        print(f"Result:\n{res4}")

    finally:
        bridge.close()

if __name__ == "__main__":
    test_match_action_pipeline()
