#!/usr/bin/env python3
"""
GHOSTSHELL Application Launcher
===============================

This script handles the complete startup process for the GHOSTSHELL application:
- (NEW) Windows preflight: mirrors netstat/tasklist/taskkill to clear prior runs
- Checks for required dependencies (Node.js, Rust/Cargo)
- Kills existing processes using required ports
- Starts the Tauri development server with frontend and backend
- Logs all output and errors to daily log files

Usage: python run.py
"""

import os
import sys
import subprocess
import time
import signal
import psutil
import shutil
import logging
import threading
import re
import platform
from datetime import datetime
from pathlib import Path

# Configuration
REQUIRED_PORTS = [5173, 1420]  # Vite dev server and Tauri default ports
NODE_PROCESS_NAMES = ["node", "node.exe"]
RUST_PROCESS_NAMES = ["cargo", "cargo.exe", "rustc", "rustc.exe"]

# Logging configuration
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

def setup_logging():
    """Setup logging with daily log files and run separators"""
    current_date = datetime.now().strftime("%Y%m%d")
    log_filename = LOG_DIR / f"ghostshell-logging-{current_date}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    separator = "=" * 80
    run_header = f"NEW RUN STARTED AT {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    with open(log_filename, 'a', encoding='utf-8') as f:
        f.write(f"\n{separator}\n")
        f.write(f"{run_header.center(80)}\n")
        f.write(f"{separator}\n\n")

    return logging.getLogger(__name__)

# Initialize logger
logger = setup_logging()

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Print the GHOSTSHELL startup banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                    GHOSTSHELL LAUNCHER                    ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)
    logger.info("GHOSTSHELL LAUNCHER - Post-Quantum Cryptography Suite")

    current_date = datetime.now().strftime("%Y%m%d")
    log_filename = LOG_DIR / f"ghostshell-logging-{current_date}.log"
    print(f"{Colors.CYAN}[LOG]{Colors.END} Logging to: {log_filename}")
    logger.info(f"Log file: {log_filename}")

def log_info(message):    print(f"{Colors.BLUE}[INFO]{Colors.END} {message}");    logger.info(message)
def log_success(message): print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}"); logger.info(f"SUCCESS: {message}")
def log_warning(message): print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}"); logger.warning(message)
def log_error(message):   print(f"{Colors.RED}[ERROR]{Colors.END} {message}");   logger.error(message)

# -------------------- Windows Preflight (mirrors your screenshot) --------------------

def _run_cmd_capture(cmd: str):
    """Run a shell command (Windows preflight) and capture stdout text."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return result.returncode, (result.stdout or "") + (result.stderr or "")
    except Exception as e:
        return 1, str(e)

def _extract_pids_from_text(text: str):
    """Extract integer PIDs from mixed command output (netstat/tasklist)."""
    pids = set()
    # PID at end of netstat lines and numeric columns in tasklist
    for line in text.splitlines():
        m = re.search(r'(\d+)\s*$', line.strip())
        if m:
            try:
                pids.add(int(m.group(1)))
            except ValueError:
                pass
    return pids

def windows_preflight_cleanup():
    """
    On Windows, emulate:
      - netstat -ano | findstr :<port>
      - tasklist | findstr node
      - tasklist | findstr -i "tauri|cargo|rustc|ghostshell"
      - taskkill /F /PID <pid>
    to ensure no previous dev instance is lingering.
    """
    if platform.system().lower() != "windows":
        return  # no-op on non-Windows

    log_info("Windows preflight: checking ports and processes (netstat/tasklist/taskkill).")

    # 1) Find PIDs listening on our required ports
    netstat_pids = set()
    for port in REQUIRED_PORTS:
        cmd = f'netstat -ano | findstr :{port}'
        rc, out = _run_cmd_capture(cmd)
        if out.strip():
            logger.info(f"[PREFLIGHT] netstat output for :{port}:\n{out.strip()}\n")
        port_pids = _extract_pids_from_text(out)
        netstat_pids |= port_pids

    # 2) Find node processes
    rc, out_node = _run_cmd_capture('tasklist | findstr node')
    if out_node.strip():
        logger.info(f"[PREFLIGHT] tasklist node:\n{out_node.strip()}\n")
    node_pids = _extract_pids_from_text(out_node)

    # 3) Find tauri/cargo/rustc/ghostshell processes (case-insensitive)
    rc, out_rust = _run_cmd_capture('tasklist | findstr -i "tauri|cargo|rustc|ghostshell"')
    if out_rust.strip():
        logger.info(f"[PREFLIGHT] tasklist tauri|cargo|rustc|ghostshell:\n{out_rust.strip()}\n")
    rust_pids = _extract_pids_from_text(out_rust)

    # Union all candidates to kill
    to_kill = set(pid for pid in (netstat_pids | node_pids | rust_pids) if pid != 0)

    if not to_kill:
        log_success("Windows preflight: no lingering processes detected.")
        return

    # 4) Kill them
    killed, failed = 0, 0
    for pid in sorted(to_kill):
        kill_cmd = f"taskkill /F /PID {pid}"
        rc, out = _run_cmd_capture(kill_cmd)
        if rc == 0:
            log_info(f"taskkill: terminated PID {pid}")
            logger.info(f"[PREFLIGHT] {kill_cmd}\n{out.strip()}\n")
            killed += 1
        else:
            log_warning(f"taskkill: failed to terminate PID {pid}")
            logger.warning(f"[PREFLIGHT] {kill_cmd}\n{out.strip()}\n")
            failed += 1

    if killed:
        log_success(f"Windows preflight: terminated {killed} process(es).")
    if failed:
        log_warning(f"Windows preflight: {failed} process(es) could not be terminated (may already be gone).")

# -------------------- Existing launcher logic (kept intact) --------------------

def check_dependencies():
    """Check if required dependencies are installed"""
    log_info("Checking dependencies...")

    # Check Node.js
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True, check=True, shell=True)
        node_version = result.stdout.strip()
        log_success(f"Node.js found: {node_version}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        log_error("Node.js not found. Please install Node.js from https://nodejs.org/")
        return False

    # Check npm
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True, check=True, shell=True)
        npm_version = result.stdout.strip()
        log_success(f"npm found: {npm_version}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        log_error("npm not found. Please install npm.")
        return False

    # Check Rust/Cargo
    try:
        result = subprocess.run(["cargo", "--version"], capture_output=True, text=True, check=True, shell=True)
        cargo_version = result.stdout.strip()
        log_success(f"Cargo found: {cargo_version}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        log_error("Cargo not found. Please install Rust from https://rustup.rs/")
        return False

    # Check Tauri CLI
    try:
        result = subprocess.run(["cargo", "tauri", "--version"], capture_output=True, text=True, check=True, shell=True)
        tauri_version = result.stdout.strip()
        log_success(f"Tauri CLI found: {tauri_version}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        log_warning("Tauri CLI not found. Installing...")
        try:
            subprocess.run(["cargo", "install", "tauri-cli"], check=True, shell=True)
            log_success("Tauri CLI installed successfully")
        except subprocess.CalledProcessError:
            log_error("Failed to install Tauri CLI")
            return False

    return True

def _terminate_then_kill(proc: psutil.Process):
    """Graceful terminate → force kill fallback."""
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

def get_processes_using_port(port):
    """Get list of processes using a specific port"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            connections = proc.connections()
            for conn in connections:
                if conn.laddr and conn.laddr.port == port:
                    processes.append(proc)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def kill_processes_by_name(process_names):
    """Kill processes by name"""
    killed_count = 0
    targets = [name.lower() for name in process_names]
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in targets:
                log_info(f"Killing process: {proc.info['name']} (PID: {proc.info['pid']})")
                _terminate_then_kill(proc)
                killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if killed_count > 0:
        log_success(f"Killed {killed_count} processes")
        time.sleep(2)  # Wait for processes to terminate

    return killed_count

def kill_processes_using_ports(ports):
    """Kill processes using specific ports"""
    killed_count = 0
    for port in ports:
        processes = get_processes_using_port(port)
        for proc in processes:
            try:
                log_info(f"Killing process using port {port}: {proc.name()} (PID: {proc.pid})")
                _terminate_then_kill(proc)
                killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    if killed_count > 0:
        log_success(f"Killed {killed_count} processes using required ports")
        time.sleep(2)  # Wait for processes to terminate

    return killed_count

def cleanup_existing_processes():
    """Clean up existing Node.js and Rust processes that might interfere"""
    log_info("Cleaning up existing processes...")

    # Kill processes using required ports
    port_kills = kill_processes_using_ports(REQUIRED_PORTS)

    # Kill Node.js processes (they might be holding ports)
    node_kills = kill_processes_by_name(NODE_PROCESS_NAMES)

    total_kills = port_kills + node_kills
    if total_kills == 0:
        log_success("No conflicting processes found")
    else:
        log_success(f"Cleanup complete. Killed {total_kills} processes")

def check_project_structure():
    """Verify the project structure is correct"""
    log_info("Checking project structure...")

    required_files = [
        "package.json",
        "src-tauri/Cargo.toml",
        "src-tauri/tauri.conf.json"
    ]

    required_dirs = [
        "src",
        "src-tauri",
        "crates"
    ]

    for file_path in required_files:
        if not Path(file_path).exists():
            log_error(f"Required file not found: {file_path}")
            return False

    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            log_error(f"Required directory not found: {dir_path}")
            return False

    log_success("Project structure verified")
    return True

def install_dependencies():
    """Install Node.js dependencies if needed"""
    log_info("Installing Node.js dependencies...")

    if not Path("node_modules").exists():
        log_info("node_modules not found, running npm install...")
        try:
            subprocess.run(["npm", "install"], check=True, shell=True)
            log_success("Dependencies installed successfully")
        except subprocess.CalledProcessError:
            log_error("Failed to install dependencies")
            return False
    else:
        log_success("Dependencies already installed")

    return True

def strip_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def log_subprocess_output(line, is_stderr=False):
    """Log subprocess output to both console and file"""
    line = line.rstrip()
    if not line:
        return

    clean_line = strip_ansi_codes(line)

    error_keywords = [
        'error:', 'error[', 'failed to', 'could not compile', 'compilation failed',
        'build failed', 'fatal:', 'panic:', 'abort', 'error occurred'
    ]

    warning_keywords = [
        'warning:', 'warning[', 'warn:', 'deprecated'
    ]

    is_actual_error = any(keyword in clean_line.lower() for keyword in error_keywords)
    is_warning = any(keyword in clean_line.lower() for keyword in warning_keywords)

    if is_actual_error:
        print(f"{Colors.RED}ERROR: {line}{Colors.END}")
        logger.error(f"SUBPROCESS: {clean_line}")
    elif is_warning:
        print(f"{Colors.YELLOW}WARNING: {line}{Colors.END}")
        logger.warning(f"SUBPROCESS: {clean_line}")
    elif is_stderr:
        print(f"{Colors.CYAN}STDERR: {line}{Colors.END}")
        logger.info(f"SUBPROCESS (stderr): {clean_line}")
    else:
        print(line)
        logger.info(f"SUBPROCESS: {clean_line}")

def start_application():
    """Start the GHOSTSHELL application"""
    log_info("Starting GHOSTSHELL application...")
    log_info("This will start both the frontend (Svelte) and backend (Rust/Tauri)")
    log_info("The application window should open automatically...")

    try:
        process = subprocess.Popen(
            ["npm", "run", "tauri:dev"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1,
            shell=True
        )

        log_success("Application started successfully!")
        log_info("Press Ctrl+C to stop the application")

        try:
            def read_stdout():
                for line in process.stdout:
                    log_subprocess_output(line, is_stderr=False)

            def read_stderr():
                for line in process.stderr:
                    log_subprocess_output(line, is_stderr=True)

            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)

            stdout_thread.start()
            stderr_thread.start()

            while process.poll() is None:
                time.sleep(0.1)

        except KeyboardInterrupt:
            log_info("Received interrupt signal, shutting down...")
            process.terminate()
            process.wait()
            log_success("Application stopped")

    except subprocess.CalledProcessError as e:
        log_error(f"Failed to start application: {e}")
        return False
    except FileNotFoundError:
        log_error("npm command not found. Please ensure Node.js is properly installed")
        return False

    return True

def log_run_end(exit_code=0, reason="Normal exit"):
    """Log the end of a run with separator"""
    current_date = datetime.now().strftime("%Y%m%d")
    log_filename = LOG_DIR / f"ghostshell-logging-{current_date}.log"

    end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    separator = "=" * 80
    end_header = f"RUN ENDED AT {end_time} - EXIT CODE: {exit_code} - REASON: {reason}"

    logger.info(f"Run ended - Exit code: {exit_code} - Reason: {reason}")

    with open(log_filename, 'a', encoding='utf-8') as f:
        f.write(f"\n{end_header.center(80)}\n")
        f.write(f"{separator}\n\n")

def main():
    """Main function"""
    exit_code = 0
    exit_reason = "Normal exit"

    try:
        print_banner()

        # Change to script directory
        script_dir = Path(__file__).parent.absolute()
        os.chdir(script_dir)
        log_info(f"Working directory: {script_dir}")

        # --- NEW: Windows preflight cleanup mirroring your manual steps ---
        windows_preflight_cleanup()

        # Step 1: Check dependencies
        if not check_dependencies():
            log_error("Dependency check failed. Please install missing dependencies.")
            exit_code = 1
            exit_reason = "Dependency check failed"
            return

        # Step 2: Check project structure
        if not check_project_structure():
            log_error("Project structure check failed. Please run this script from the GHOSTSHELL root directory.")
            exit_code = 1
            exit_reason = "Project structure check failed"
            return

        # Step 3: Clean up existing processes
        cleanup_existing_processes()

        # Step 4: Install dependencies
        if not install_dependencies():
            log_error("Failed to install dependencies.")
            exit_code = 1
            exit_reason = "Failed to install dependencies"
            return

        # Step 5: Start the application
        log_info("All checks passed! Starting application...")
        time.sleep(1)

        if not start_application():
            log_error("Failed to start application.")
            exit_code = 1
            exit_reason = "Failed to start application"
            return

    except KeyboardInterrupt:
        log_info("Startup interrupted by user")
        exit_code = 0
        exit_reason = "User interrupt"
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        exit_code = 1
        exit_reason = f"Unexpected error: {str(e)}"
    finally:
        log_run_end(exit_code, exit_reason)
        sys.exit(exit_code)

if __name__ == "__main__":
    # Check if psutil is available
    try:
        import psutil
    except ImportError:
        print(f"{Colors.RED}[ERROR]{Colors.END} psutil module not found.")
        print(f"{Colors.YELLOW}[INFO]{Colors.END} Installing psutil...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
            import psutil
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} psutil installed successfully")
        except subprocess.CalledProcessError:
            print(f"{Colors.RED}[ERROR]{Colors.END} Failed to install psutil. Please install it manually:")
            print("pip install psutil")
            sys.exit(1)

    main()
