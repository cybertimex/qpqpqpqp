# -*- coding: utf-8 -*-
import subprocess
import time
import sys
import threading
from queue import Queue, Empty

# --- Settings ---
# The script file you want to run and monitor
SCRIPT_TO_RUN = "main.py" 
# Restart timeout (in seconds). If no output is received during this time, the process will be restarted.
# (2 minutes 30 seconds = 150 seconds)
RESTART_TIMEOUT_SECONDS = 150

def enqueue_output(process, queue):
    """
    This function runs in a separate thread to read the script's output 
    and put it into a queue.
    """
    try:
        # Read the output line by line
        for line in iter(process.stdout.readline, ''):
            queue.put(line)
        process.stdout.close()
    except Exception:
        # This may fail if the process is killed suddenly
        pass

def run_and_monitor():
    """
    Main function to run and monitor the script.
    """
    # Infinite loop to keep monitoring
    while True:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting script '{SCRIPT_TO_RUN}'...")
        try:
            # Command to run the Python script
            process = subprocess.Popen(
                [sys.executable, SCRIPT_TO_RUN],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding='utf-8'
            )
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Script started successfully. Process ID: {process.pid}")

        except FileNotFoundError:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error: file '{SCRIPT_TO_RUN}' not found. Please check the filename.")
            break  # Exit if the script file doesn’t exist
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Failed to start script: {e}. Retrying in 10 seconds...")
            time.sleep(10)
            continue

        # Use a queue to get outputs from the reading thread
        output_queue = Queue()
        reader_thread = threading.Thread(target=enqueue_output, args=(process, output_queue))
        reader_thread.daemon = True  # End the thread when the main program exits
        reader_thread.start()

        last_output_time = time.time()

        # Monitoring loop for the current process
        while True:
            # 1. Check if the script has stopped running
            if process.poll() is not None:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Script stopped unexpectedly. Restarting...")
                break  # Exit monitoring loop → restart in the outer loop

            # 2. Check for new output
            try:
                # Try to get a new line from the output
                line = output_queue.get_nowait()
                print(line, end='')  # Print script output
                last_output_time = time.time()  # Update last response time
            except Empty:
                # No new output → check how long it’s been idle
                time_since_last_output = time.time() - last_output_time
                if time_since_last_output > RESTART_TIMEOUT_SECONDS:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] No new output for more than {RESTART_TIMEOUT_SECONDS} seconds. Restarting...")
                    process.kill()  # Kill the current process
                    process.wait()  # Ensure it’s fully stopped
                    break  # Exit monitoring loop → restart

            time.sleep(1)  # Wait 1 second before checking again

if __name__ == "__main__":
    run_and_monitor()