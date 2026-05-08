import sys
import os
import importlib.util

# Ensure the project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Try importing the CLI as a package
try:
    from razorscan.cli import app
except Exception:
    # Fallback: load cli.py directly from the package directory
    cli_path = os.path.join(BASE_DIR, "razorscan", "cli.py")
    spec = importlib.util.spec_from_file_location("cli", cli_path)
    cli_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli_module)
    app = cli_module.app

if __name__ == "__main__":
    app()
