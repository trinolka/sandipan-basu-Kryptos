#!/usr/bin/env python
import sys

class TerminalUserInterface:
    def clear_screen(self):
        # Direct ANSI terminal escape sequences to reset cursor coordinates
        print("\033[H\033[2J", end="")
        sys.stdout.flush()
        
    def render_double_box(self, structural_title, line_arrays):
        # Renders beautiful structured dashboard panels using safe flat characters
        border_width = 76
        print("+" + "-" * border_width + "+")
        print(f"| {structural_title.center(border_width)} |")
        print("+" + "-" * border_width + "+")
        
        for dynamic_line in line_arrays:
            print(f"| {dynamic_line.ljust(border_width)} |")
            
        print("+" + "-" * border_width + "+")
        sys.stdout.flush()

    def print_alert_bar(self, current_frame):
        # Renders a shifting loading progress alert ticker string
        block_count = (current_frame % 8) + 1
        indicator = ">>>" * block_count
        print(f"\033[1;33m[ALERT TELEMETRY PIPELINE STREAM ACTIVE] {indicator.ljust(24)}\033[0m")
        sys.stdout.flush()

if __name__ == '__main__':
    print("[Module Verification]: x3.py successfully linked.")
    sys.exit(0)
