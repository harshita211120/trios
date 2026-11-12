import os

# 1. Define allowed tools and required arguments[cite: 2]
TOOLS = {
    "list_files": {
        "required": [],
        "types": {}
    },
    "read_file": {
        "required": ["path"],
        "types": {"path": str}
    },
    "summarize": {
        "required": ["text"],
        "types": {"text": str}
    },
}

# Restrict file access strictly to a safe relative sandbox area
ALLOWED_DIR = "./guest_workspace"


class ValidationError(Exception):
    """Custom exception raised when action validation fails."""
    pass


def validate_action(action: dict) -> bool:
    """
    Validates model/user action against allowed tool schemas and path safety rules[cite: 2, 4].
    Must reject unknown tools, missing/wrongly typed args, and unsafe paths[cite: 2, 4].
    """
    # Check basic JSON/dict structure
    if not isinstance(action, dict):
        raise ValidationError("Action must be a valid dictionary/object.")

    tool_name = action.get("tool")
    args = action.get("args")

    if not tool_name or args is None or not isinstance(args, dict):
        raise ValidationError("Action must contain 'tool' (str) and 'args' (dict).")

    # 1. Reject unknown tool names[cite: 2]
    if tool_name not in TOOLS:
        raise ValidationError(f"Unknown tool '{tool_name}'. Allowed: {list(TOOLS.keys())}")

    schema = TOOLS[tool_name]

    # 2. Check for missing required arguments[cite: 2]
    for req_arg in schema["required"]:
        if req_arg not in args:
            raise ValidationError(f"Missing required argument '{req_arg}' for tool '{tool_name}'.")

    # 3. Check argument data types[cite: 2]
    for arg_name, expected_type in schema["types"].items():
        if arg_name in args and not isinstance(args[arg_name], expected_type):
            raise ValidationError(
                f"Argument '{arg_name}' must be of type {expected_type.__name__}, "
                f"got {type(args[arg_name]).__name__}."
            )

    # 4. Security Check: Restrict file paths to the allowed exercise area[cite: 2, 4]
    if "path" in args:
        raw_path = args["path"]
        
        # Prevent path traversal attacks (e.g., '../', absolute paths like '/etc/passwd')[cite: 2, 4]
        if raw_path.startswith("/") or ".." in raw_path:
            raise ValidationError(f"Path traversal or absolute path detected: '{raw_path}'. Restricted to workspace.")

    return True
    
class ToolDispatcher:
    def __init__(self, bridge):
        """
        Receives an active QEMUBridge instance[cite: 2, 3].
        """
        self.bridge = bridge

    def execute(self, action: dict) -> str:
        tool_name = action["tool"]
        args = action["args"]

        # Map approved actions to fixed xv6 system utilities[cite: 2]
        if tool_name == "list_files":
            cmd = "ls"
        elif tool_name == "read_file":
            cmd = f"cat {args['path']}"
        elif tool_name == "summarize":
            # Summarize operates on text on the host side
            return f"Observation Summary: {args['text']}"
        else:
            return f"Execution Error: Unsupported tool '{tool_name}'"

        # Execute mapped command over QEMU bridge[cite: 2, 3]
        guest_output = self.bridge.send_command(cmd)
        return f"Observation:\n{guest_output}"
