import re
from tools import validate_action, ValidationError

class MatchActionPlanner:
    """
    Implements a networking-style Match-Action Table for agent planning[cite: 3].
    Matches incoming request patterns to predefined flow entry actions[cite: 2, 3].
    """
    def __init__(self):
        # Match-Action Flow Table Entries
        # Supports: 'exact', 'prefix', and 'regex' (ternary/wildcard) match fields
        self.flow_table = [
            # Flow 1: Exact Match for listing directory contents[cite: 3]
            {
                "match_type": "exact",
                "pattern": "list",
                "action": {"tool": "list_files", "args": {}}
            },
            # Flow 2: Prefix Match for listing directory contents[cite: 3]
            {
                "match_type": "prefix",
                "pattern": "show files",
                "action": {"tool": "list_files", "args": {}}
            },
            # Flow 3: Regex Pattern Match for read_file with path extraction[cite: 3]
            {
                "match_type": "regex",
                "pattern": r"^(?:read|cat)\s+(?P<path>\S+)$",
                "action_template": {"tool": "read_file", "args": {"path": "{path}"}}
            },
            # Flow 4: Rule testing forbidden/malicious proposal (for safety/firewall testing)
            {
                "match_type": "prefix",
                "pattern": "delete",
                "action": {"tool": "delete_file", "args": {"path": "/important.txt"}}
            }
        ]

    def lookup(self, user_request: str) -> dict:
        """
        Parses incoming 'packet' (user_request) against flow table entries[cite: 3].
        Returns the mapped structured action on hit, or None on table miss[cite: 3].
        """
        request_clean = user_request.strip()

        for entry in self.flow_table:
            m_type = entry["match_type"]
            pattern = entry["pattern"]

            # 1. Exact Match Rule
            if m_type == "exact" and request_clean.lower() == pattern.lower():
                return entry["action"]

            # 2. Prefix Match Rule
            elif m_type == "prefix" and request_clean.lower().startswith(pattern.lower()):
                return entry["action"]

            # 3. Regex / Ternary Wildcard Match Rule with Field Extraction
            elif m_type == "regex":
                match = re.match(pattern, request_clean, re.IGNORECASE)
                if match:
                    if "action" in entry:
                        return entry["action"]
                    elif "action_template" in entry:
                        # Extract parsed fields (e.g., path parameter)
                        extracted_args = match.groupdict()
                        return {
                            "tool": entry["action_template"]["tool"],
                            "args": {"path": extracted_args.get("path", "")}
                        }

        # Table Miss (No matching rule found)
        return None


class MatchActionAgent:
    def __init__(self, tools, planner: MatchActionPlanner):
        self.tools = tools
        self.planner = planner

    def run(self, user_request: str) -> str:
        print(f"\n[Switch Ingress] Incoming Packet: '{user_request}'")

        # Step 1: Match-Action Table Lookup[cite: 3]
        proposed_action = self.planner.lookup(user_request)

        if not proposed_action:
            return "[Switch Egress] TABLE MISS: No flow entry rule matched the request."

        print(f"[Match-Action Table HIT] Matched Rule -> Proposed Action: {proposed_action}")

        # Step 2: Validate Action Schema & Path Policy (Firewall/Validator)
        try:
            validate_action(proposed_action)
        except ValidationError as e:
            return f"[Validator ACL Blocked Action]: {e}"

        # Step 3: Execute Action via QEMU Bridge[cite: 2, 3]
        return self.tools.execute(proposed_action)
