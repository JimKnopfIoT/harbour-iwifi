#!/usr/bin/env python3
# Generates the harbour-iwifi app icon:
#   orange skull in front; behind it grey Wi-Fi arc-fans in all four directions
#   that glow orange toward the outside, the arcs thinning as they go outward.
import math, subprocess, os

C = 128.0          # centre of a 256 viewBox

def arc(r, deg_center, span, w, color, opacity=1.0):
    a0 = math.radians(deg_center - span)
    a1 = math.radians(deg_center + span)
    sx, sy = C + r * math.cos(a0), C + r * math.sin(a0)
    ex, ey = C + r * math.cos(a1), C + r * math.sin(a1)
    return ('<path d="M %.1f %.1f A %.1f %.1f 0 0 1 %.1f %.1f" '
            'stroke="%s" stroke-width="%.1f" stroke-linecap="round" '
            'fill="none" stroke-opacity="%.2f"/>') % (sx, sy, r, r, ex, ey, color, w, opacity)

# Wi-Fi fans: 4 directions, 3 rings each. Inner = grey & thick, outer = orange & thin.
rings = [
    # radius, stroke, colour
    (60, 12, "#8c8c8c"),
    (86,  7, "#d07b2c"),
    (112, 4, "#ff7a00"),
]
dirs = [-90, 0, 90, 180]   # up, right, down, left
SPAN = 30                  # < 45 so the four fans stay separate (clear gaps)

arcs_glow = []
arcs = []
for d in dirs:
    for r, w, col in rings:
        arcs.append(arc(r, d, SPAN, w, col))
        if col == "#ff7a00":                      # outer ring also glows
            arcs_glow.append(arc(r, d, SPAN, w + 3, "#ff7a00", 0.9))

skull = '''
  <!-- skull -->
  <g>
    <circle cx="128" cy="116" r="46" fill="#ff6d00"/>
    <path d="M 102 150 Q 102 186 128 188 Q 154 186 154 150 Z" fill="#ff6d00"/>
    <!-- eye sockets -->
    <ellipse cx="110" cy="114" rx="13" ry="16" fill="#1a0a00"/>
    <ellipse cx="146" cy="114" rx="13" ry="16" fill="#1a0a00"/>
    <!-- nose -->
    <path d="M 128 128 L 120 144 L 136 144 Z" fill="#1a0a00"/>
    <!-- mouth + teeth -->
    <path d="M 110 162 L 146 162" stroke="#1a0a00" stroke-width="4" stroke-linecap="round"/>
    <path d="M 119 162 L 119 182" stroke="#1a0a00" stroke-width="4" stroke-linecap="round"/>
    <path d="M 128 162 L 128 184" stroke="#1a0a00" stroke-width="4" stroke-linecap="round"/>
    <path d="M 137 162 L 137 182" stroke="#1a0a00" stroke-width="4" stroke-linecap="round"/>
  </g>
'''

svg = '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <defs>
    <filter id="glow" x="-30%%" y="-30%%" width="160%%" height="160%%">
      <feGaussianBlur stdDeviation="4"/>
    </filter>
  </defs>
  <g filter="url(#glow)" opacity="0.7">
    %s
  </g>
  <g>
    %s
  </g>
  %s
</svg>
''' % ("\n    ".join(arcs_glow), "\n    ".join(arcs), skull)

here = os.path.dirname(os.path.abspath(__file__))
svg_path = os.path.join(here, "icon.svg")
with open(svg_path, "w") as f:
    f.write(svg)

for size in (86, 108, 128, 172, 256):
    out = os.path.join(here, "%dx%d" % (size, size), "harbour-iwifi.png")
    subprocess.check_call(["rsvg-convert", "-w", str(size), "-h", str(size),
                           "-o", out, svg_path])
    print("wrote", out)

# Also refresh the in-app About logo (qml/harbour-iwifi.png), so it never drifts
# back to the old upstream artwork.
about = os.path.join(here, "..", "qml", "harbour-iwifi.png")
subprocess.check_call(["rsvg-convert", "-w", "256", "-h", "256",
                       "-o", about, svg_path])
print("wrote", about)
