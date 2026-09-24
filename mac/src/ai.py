#!/usr/bin/env python
import queue
import sys

print("ai.py: Starting module initialization...")
print("ai.py: Antivirus AI module initialized in Local Bypass Mode.")
print("ai.py: Module initialization complete.")

scan_results_queue = queue.Queue()

def add_to_queue(item):
    scan_results_queue.put(item)

def get_queue_contents():
    contents = []
    while not scan_results_queue.empty():
        contents.append(scan_results_queue.get())
    return contents

def generate_prompt(prompt):
    prompt_lower = prompt.lower().strip()
    
    if "process" in prompt_lower or "running" in prompt_lower:
        return "SCAN_PROCESSES"
    elif prompt_lower.startswith("scan "):
        # Extract custom path if provided after 'scan '
        path_arg = prompt.strip()[5:].strip()
        if path_arg:
            return f"SCAN_FOLDER:{path_arg}"
        return "SCAN_FOLDER:."
    elif prompt_lower == "scan":
        return "SCAN_FOLDER:."
    
    return "Antivirus AI assistant is running in local fallback mode. Type 'scan [path]' or ask to scan processes."
