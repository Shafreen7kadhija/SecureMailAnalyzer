import os

icons_dir = os.path.dirname(os.path.abspath(__file__))

svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#06b6d4" />
      <stop offset="100%" stop-color="#1e3a8a" />
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="28" fill="#090d16" />
  <path d="M64 16 L104 32 V68 C104 94 64 112 64 112 C64 112 24 94 24 68 V32 Z" fill="url(#shieldGrad)" stroke="#38bdf8" stroke-width="3" />
  <path d="M52 64 L60 72 L78 52" fill="none" stroke="#ffffff" stroke-width="7" stroke-linecap="round" stroke-linejoin="round" />
</svg>"""

with open(os.path.join(icons_dir, "icon.svg"), "w", encoding="utf-8") as f:
    f.write(svg_content)

print("Icon created.")
