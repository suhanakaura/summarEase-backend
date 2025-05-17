import sys
import json
import platform

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        result = {
            "status": "OK",
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "message": "Test script executed successfully"
        }
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps({"status": "Error", "message": "Use --test argument"}, indent=2))