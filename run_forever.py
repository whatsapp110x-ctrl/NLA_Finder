"""
A helper script to ensure the Telegram bot stays up 24/7.

This module continuously launches the main bot module and restarts it
automatically if the process exits for any reason.  Render and other
PaaS providers will normally restart failed processes, but in
circumstances where the bot might crash unexpectedly, this wrapper
provides an extra layer of resilience.

Example usage (from render.yaml):

  startCommand: python run_forever.py

This script spawns a child process running `python IPScanBot/main.py`.
If the child exits, it waits a few seconds and then restarts it.  To
stop the wrapper gracefully, send a SIGTERM or SIGINT (Ctrl+C) to
this process; it will propagate the signal to the child and exit.
"""

import subprocess
import time
import os
import signal
from typing import Optional


def run_bot_forever() -> None:
    """Run the Telegram bot in a loop, restarting on unexpected exit.

    This function will launch `python IPScanBot/main.py` as a subprocess.
    If the subprocess terminates, this function will log the exit code
    and restart the subprocess after a short delay.  Use environment
    variables BOT_TOKEN, DEFAULT_TIMEOUT, and MAX_CONCURRENT_SCANS as
    you would when running the bot directly.
    """
    # Use an environment copy to ensure we propagate existing env vars
    env = os.environ.copy()
    # Command to run the bot module
    command = ["python", "IPScanBot/main.py"]

    # Define a handler to forward termination signals to the child
    child: Optional[subprocess.Popen] = None

    def terminate_child(signum, frame):
        if child and child.poll() is None:
            try:
                child.terminate()
            except Exception:
                pass
        raise SystemExit(0)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, terminate_child)
    signal.signal(signal.SIGINT, terminate_child)

    while True:
        try:
            child = subprocess.Popen(command, env=env)
            exit_code = child.wait()
            # If the bot exits cleanly (exit code 0), we break the loop
            if exit_code == 0:
                break
            # Otherwise, log and restart after delay
            print(f"Bot exited with code {exit_code}. Restarting in 5 seconds...")
            time.sleep(5)
        except (KeyboardInterrupt, SystemExit):
            # Propagate keyboard interrupt
            if child and child.poll() is None:
                try:
                    child.terminate()
                except Exception:
                    pass
            break
        except Exception as e:
            # Catch unexpected errors, wait and retry
            print(f"Wrapper encountered an error: {e}. Restarting in 5 seconds...")
            time.sleep(5)


if __name__ == "__main__":
    run_bot_forever()