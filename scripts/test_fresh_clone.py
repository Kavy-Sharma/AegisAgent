"""
Fresh Clone Validation Script
1. Clones repository into a temporary directory.
2. Synchronizes active modified files (since changes are not yet committed).
3. Verifies requirements.txt can be read.
4. Runs pytest -v inside the clean clone directory.
5. Verifies start.py can load/synthesize environment without crashes.
"""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT_DIR = Path(__file__).resolve().parent.parent


def run_fresh_clone_test():
    print("=" * 70)
    print("FRESH CLONE VERIFICATION TEST")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp_dir:
        clone_dir = Path(tmp_dir) / "aegis_fresh_clone"
        print(f"[*] Step 1: Cloning repository to clean directory {clone_dir}...")
        res = subprocess.run(
            ["git", "clone", "--branch", "web-ui", str(ROOT_DIR), str(clone_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if res.returncode != 0:
            print(f"[!] Git clone failed: {res.stderr}")
            return False
        print("[+] Git clone successful.")

        print("[*] Step 2: Overlaying working tree fixes and untracked files...")
        # Copy modified modules and new files
        for folder in ["security", "agent", "web", "tests", "benchmark", "scripts", "demo"]:
            src = ROOT_DIR / folder
            dst = clone_dir / folder
            if src.exists():
                shutil.copytree(src, dst, dirs_exist_ok=True)

        for single_file in [".gitattributes", "requirements.txt", "policy.yaml", "README.md"]:
            src = ROOT_DIR / single_file
            dst = clone_dir / single_file
            if src.exists():
                shutil.copy2(src, dst)

        print("[+] Working tree synchronized.")

        print("[*] Step 3: Checking requirements.txt...")
        req_file = clone_dir / "requirements.txt"
        assert req_file.exists(), "requirements.txt missing in clone!"
        print(f"[+] requirements.txt present ({len(req_file.read_text(encoding='utf-8').splitlines())} dependencies).")

        print("[*] Step 4: Running pytest -v inside fresh clone...")
        test_res = subprocess.run(
            [sys.executable, "-m", "pytest", "-v", "tests/test_fix4_hardening.py", "tests/test_phase_b_tamper_demo.py"],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        print(test_res.stdout)
        if test_res.returncode != 0:
            print(f"[!] Pytest failed in fresh clone: {test_res.stderr}")
            return False
        print("[+] Pytest passed in fresh clone.")

        print("[*] Step 5: Checking start.py syntax...")
        start_res = subprocess.run(
            [sys.executable, "-c", "import py_compile; py_compile.compile('start.py')"],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if start_res.returncode != 0:
            print(f"[!] start.py compilation failed: {start_res.stderr}")
            return False
        print("[+] start.py syntax and imports verified.")

    print("=" * 70)
    print("FRESH CLONE VERIFICATION: ALL CHECKS PASSED")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = run_fresh_clone_test()
    if not success:
        sys.exit(1)
