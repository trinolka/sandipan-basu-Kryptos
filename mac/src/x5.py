#!/usr/bin/env python
import sys
import os
import time

# Synchronize runtime physical folder path environments
runtime_dir = os.path.dirname(os.path.abspath(__file__))
if runtime_dir not in sys.path:
    sys.path.insert(0, runtime_dir)

from x1 import IdentityRegistry
from x2 import GraphicFieldEngine
from x3 import TerminalUserInterface

def launch_investor_dashboard():
    registry = IdentityRegistry()
    field_plotter = GraphicFieldEngine()
    console_ui = TerminalUserInterface()
    
    # 20 consecutive frames of clean, real-time animated console outputs
    for frame in range(20):
        console_ui.clear_screen()
        
        print("\033[1;32m================================================================================")
        print("          KRYPTOS ZERO-TRUST ENGINE: DYNAMIC MONOLITH REAL-TIME VIEW")
        print("================================================================================\033[0m\n")
        
        # Pull live computed metadata blocks from x1.py
        data_block = registry.get_crypto_metadata(segment_index=frame)
        logger_payload = [
            f"CORE ARCHITECTURE SCHEME : {registry.algorithm_family}",
            f"ACTIVE NODE IDENTIFIER   : {data_block['active_node']}",
            f"HIGH-ENTROPY LEVEL METER : {data_block['entropy']}",
            f"STREAM SECURE ENVELOPE   : {data_block['cipher']}",
            f"VIRTUAL-LOCK SYSTEM PAGE : {data_block['signature']}"
        ]
        console_ui.render_double_box("SECURE HARDWARE CORE TELEMETRY TRACKER", logger_payload)
        print("\n")
        
        # Compute waving graph calculations dynamically from x2.py
        time_clock_delta = frame * 0.28
        ascii_grid_matrix = field_plotter.generate_ascii_plot_frame(time_clock_delta)
        console_ui.render_double_box("LIVE CYCLICAL METRIC VECTOR PLOT FIELD (FILELESS RAM ENGINE)", ascii_grid_matrix)
        print("\n")
        
        console_ui.print_alert_bar(frame)
        print(f"\033[1;30m[Frame Clock Cycle: {frame + 1}/20] - Streaming directly out of memory arrays...\033[0m")
        sys.stdout.flush()
        
        # Smooth render clock timing delay step
        time.sleep(0.12)
        
    print("\n\033[1;32m[🚀] SUCCESS: Real-time graphical investor demonstration loop finalized complete!\033[0m")

if __name__ == '__main__':
    print("Welcome to the Text RPG Engine demo!")
    try:
        launch_investor_dashboard()
    except KeyboardInterrupt:
        print("\n[-] Dynamic performance loop terminated by system user break signal.")
    sys.exit(0)
