from tools import validate_action, ValidationError

def run_tests():
    print("--- Running Milestone B Validator Tests ---")

    # Test 1: Valid list_files action[cite: 4]
    try:
        action = {"tool": "list_files", "args": {}}
        validate_action(action)
        print("[PASS] Valid list_files accepted.")
    except ValidationError as e:
        print(f"[FAIL] Valid list_files rejected: {e}")

    # Test 2: Valid read_file action[cite: 4]
    try:
        action = {"tool": "read_file", "args": {"path": "README"}}
        validate_action(action)
        print("[PASS] Valid read_file accepted.")
    except ValidationError as e:
        print(f"[FAIL] Valid read_file rejected: {e}")

    # Test 3: Reject unknown tool[cite: 2, 4]
    try:
        action = {"tool": "delete_file", "args": {"path": "README"}}
        validate_action(action)
        print("[FAIL] Unknown tool 'delete_file' was incorrectly accepted!")
    except ValidationError:
        print("[PASS] Unknown tool rejected successfully.")

    # Test 4: Reject missing required argument[cite: 2, 4]
    try:
        action = {"tool": "read_file", "args": {}}
        validate_action(action)
        print("[FAIL] Missing argument call was incorrectly accepted!")
    except ValidationError:
        print("[PASS] Missing required argument rejected successfully.")

    # Test 5: Reject dangerous path traversal[cite: 2, 4]
    try:
        action = {"tool": "read_file", "args": {"path": "../../../etc/passwd"}}
        validate_action(action)
        print("[FAIL] Dangerous path traversal was incorrectly accepted!")
    except ValidationError:
        print("[PASS] Path traversal attempt blocked successfully.")

if __name__ == "__main__":
    run_tests()
