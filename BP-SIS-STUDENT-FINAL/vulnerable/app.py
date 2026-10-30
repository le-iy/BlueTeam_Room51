from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from bp_sis.app import create_app

app = create_app("vulnerable")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(__import__("os").environ.get("BP_SIS_PORT", "8765")), debug=False)
