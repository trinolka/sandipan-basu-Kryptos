#!/usr/bin/env python
import tkinter as tk
import math

class FractalApp:
    def __init__(self, root):
        self.root = root
        self.canvas = tk.Canvas(root, width=600, height=500, bg='black', highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.canvas.bind("<Motion>", self.on_mouse_move)
        self.angle_factor = 0.5
        self.draw_tree()

    def draw_branch(self, x1, y1, angle, depth):
        if depth == 0:
            return
        
        length = depth * 8
        x2 = x1 + int(math.cos(math.radians(angle)) * length)
        y2 = y1 + int(math.sin(math.radians(angle)) * length)
        
        green = int((depth / 10.0) * 255)
        red = 255 - green
        color = f"#{red:02x}{green:02x}00"
        
        self.canvas.create_line(x1, y1, x2, y2, fill=color, width=depth*0.7)
        
        self.draw_branch(x2, y2, angle - (30 * self.angle_factor), depth - 1)
        self.draw_branch(x2, y2, angle + (30 * self.angle_factor), depth - 1)

    def draw_tree(self):
        self.canvas.delete("all")
        self.draw_branch(300, 480, -90, 10)

    def on_mouse_move(self, event):
        self.angle_factor = max(0.1, (event.x / 600.0) * 2.0)
        self.draw_tree()
