#!/usr/bin/env python
import tkinter as tk
import sys
import os
import threading
import time

# Ensure local fileless memory execution context imports resolve cleanly
import v1
import v2

class Orchestrator:
    def __init__(self, root):
        self.root = root
        self.root.title("Impromptu Graphical Laboratory")
        self.root.geometry("600x550")
        self.root.minsize(600, 550)
        
        # Intercept the window closing "X" event gracefully
        self.root.protocol("WM_DELETE_WINDOW", self.on_terminate_pipeline)
        
        # Control Frame layout
        self.control_frame = tk.Frame(root, bg='#222', height=50)
        self.control_frame.pack(fill=tk.X, side=tk.TOP)
        
        # View Container
        self.display_frame = tk.Frame(root, bg='black')
        self.display_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control triggers
        btn_fractal = tk.Button(self.control_frame, text="Load Fractal Workspace", command=self.load_fractal, bg='#444', fg='white')
        btn_fractal.pack(side=tk.LEFT, padx=20, pady=10)
        
        btn_particles = tk.Button(self.control_frame, text="Load Particle Simulation", command=self.load_particles, bg='#444', fg='white')
        btn_particles.pack(side=tk.LEFT, padx=20, pady=10)
        
        # Initialize default view
        self.current_app = None
        self.load_fractal()

    def on_terminate_pipeline(self):
        """Cross-platform termination logic that safely drops the parent process loop
        without leaving headless zombie threads behind.
        """
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass
            
        parent_pid = os.getppid()
        if parent_pid > 1:
            try:
                if sys.platform == "win32":
                    os.system(f"taskkill /F /PID {parent_pid}")
                else:
                    import signal
                    os.kill(parent_pid, signal.SIGKILL)
            except Exception:
                pass
        sys.exit(0)

    def clear_display(self):
        for widget in self.display_frame.winfo_children():
            widget.destroy()

    def load_fractal(self):
        self.clear_display()
        self.current_app = v1.FractalApp(self.display_frame)

    def load_particles(self):
        self.clear_display()
        self.current_app = v2.ParticleSystem(self.display_frame)

def run_non_blocking_gui():
    """FIXED DESKTOP ENGAGEMENT: Forces Tkinter's window loop out of the 
    stuck console pipe context so X11 graphics can render asynchronously.
    """
    root = tk.Tk()
    app = Orchestrator(root)
    
    # Force the display to refresh immediately to keep the window responsive
    root.update_idletasks()
    root.update()
    root.mainloop()

if __name__ == "__main__":
    # If standard output or input is buffered or running inside an automated console pipe,
    # offload the interface thread to avoid deadlocking the execution runtime
    if not sys.stdout.isatty():
        gui_thread = threading.Thread(target=run_non_blocking_gui, daemon=True)
        gui_thread.start()
        
        # Keep the main channel pipe alive silently while the user interacts with the canvas window
        try:
            while gui_thread.is_alive():
                time.sleep(0.1)
        except (KeyboardInterrupt, SystemExit):
            sys.exit(0)
    else:
        # Standard fallback if run directly from a normal visible shell session
        root = tk.Tk()
        app = Orchestrator(root)
        root.mainloop()