#!/usr/bin/env python
import tkinter as tk
import random

class ParticleSystem:
    def __init__(self, root):
        self.root = root
        self.canvas = tk.Canvas(root, width=600, height=500, bg='#111122', highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        self.particles = []
        colors = ['#FF5733', '#33FF57', '#3357FF', '#F3FF33', '#FF33F3', '#33FFF0']
        
        for _ in range(40):
            self.particles.append({
                'id': self.canvas.create_oval(0, 0, 12, 12, fill=random.choice(colors), outline=''),
                'x': random.randint(50, 550),
                'y': random.randint(50, 450),
                'vx': random.choice([-3, -2, -1, 1, 2, 3]),
                'vy': random.choice([-3, -2, -1, 1, 2, 3])
            })
        self.animate()

    def animate(self):
        # Prevent animation loops from crashing if widgets are torn down out of view context
        try:
            for p in self.particles:
                p['x'] += p['vx']
                p['y'] += p['vy']
                
                if p['x'] <= 0 or p['x'] >= 588: p['vx'] *= -1
                if p['y'] <= 0 or p['y'] >= 488: p['vy'] *= -1
                
                self.canvas.coords(p['id'], p['x'], p['y'], p['x'] + 12, p['y'] + 12)
                
            self.root.after(20, self.animate)
        except Exception:
            pass