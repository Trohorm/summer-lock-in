#!/usr/bin/env python3
"""Draw the Summer Lock In dumbbell app icon (same design as the web app)."""
import sys
from PIL import Image, ImageDraw

out = sys.argv[1] if len(sys.argv) > 1 else "icon-1024.png"
SZ = 1024
S = SZ / 64.0  # design was made on a 64x64 grid

img = Image.new("RGB", (SZ, SZ), "#0e1013")
d = ImageDraw.Draw(img)

def rr(x, y, w, h, r, color):
    d.rounded_rectangle([x*S, y*S, (x+w)*S, (y+h)*S], radius=r*S, fill=color)

BLUE, WHITE = "#5b93ff", "#e9ecf1"
rr(8, 27, 6, 10, 2, BLUE)    # outer plates
rr(50, 27, 6, 10, 2, BLUE)
rr(15, 23, 7, 18, 2, BLUE)   # inner plates
rr(42, 23, 7, 18, 2, BLUE)
rr(22, 30, 20, 4, 2, WHITE)  # bar

img.save(out, "PNG")
print("wrote", out)
