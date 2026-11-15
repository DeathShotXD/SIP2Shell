#!/usr/bin/env python3
"""Render a terminal-style GIF from a real SIP2Shell lab session.

The lines below are copied verbatim from an actual run against the included
safarov/freeswitch:1.10.12 lab container. No output is invented.
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 960, 400
FPS = 12
FRAME = int(1000 / FPS)
BG = (7, 6, 7)
PANEL = (10, 8, 9)
BONE = (240, 226, 200)
DIM = (138, 122, 102)
RED = (255, 90, 90)
DEEP = (212, 20, 20)
GREEN = (142, 240, 122)
AMBER = (240, 180, 90)
TEAL = (53, 208, 192)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
f = ImageFont.truetype(MONO, 17)
fb = ImageFont.truetype(MONO_B, 17)
f_small = ImageFont.truetype(MONO, 13)
f_title = ImageFont.truetype(MONO_B, 14)

LEFT = 52
TOP = 104
LH = 25

CMD1 = 'python3 sip2shell.py probe -t 192.168.0.111'
OUT1 = [
    ("  VULN 192.168.0.111:5060       vulnerable v1.10.12", RED),
]
CMD2 = 'python3 sip2shell.py exploit -t 192.168.0.111 -c "id; hostname; uname -sr"'
OUT2 = [
    ("[*] target 192.168.0.111:5060", DIM),
    ("    OOB listener on http://192.168.0.111:41871/tbz867", AMBER),
    ("uid=0 gid=0 groups=0", GREEN),
    ("kali", BONE),
    ("Linux 7.1.5+kali-amd64", BONE),
]

# lines: (prefix, text, colour); prefix is the "$ " marker, coloured separately
frames = []  # list of (lines, cursor_visible)


def base():
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    # window
    d.rounded_rectangle([24, 24, W - 24, H - 24], radius=12, fill=PANEL,
                        outline=(48, 22, 22), width=1)
    d.line([24, 68, W - 24, 68], fill=(52, 22, 22))
    for i, c in enumerate((DEEP, AMBER, TEAL)):
        d.ellipse([52 + i * 22, 40, 62 + i * 22, 50], fill=c)
    d.text((126, 39), "sip2shell / lab", font=f_title, fill=DIM)
    d.text((W - 52, 39), "AUTHORIZED LAB", font=f_title, fill=RED, anchor="ra")
    return im, d


def render(lines, cursor=True, typed=None):
    im, d = base()
    y = TOP
    for item in lines:
        kind = item[0]
        if kind == "cmd":
            _, text, done = item
            d.text((LEFT, y), "$", font=fb, fill=DEEP)
            d.text((LEFT + 22, y), text[:done], font=f, fill=BONE)
        elif kind == "out":
            _, text, col = item
            d.text((LEFT, y), text, font=f, fill=col)
        y += LH
    if cursor:
        # place the block after the last visible character
        if lines and lines[-1][0] == "cmd":
            _, text, done = lines[-1]
            x = LEFT + 22 + d.textlength(text[:done], font=f)
            d.rectangle([x + 2, y - LH + 2, x + 12, y - LH + 18], fill=BONE)
        elif lines and lines[-1][0] == "out":
            _, text, _ = lines[-1]
            x = LEFT + d.textlength(text, font=f)
            d.rectangle([x + 2, y - LH + 2, x + 12, y - LH + 18], fill=BONE)
        else:
            d.rectangle([LEFT + 24, y + 2, LEFT + 34, y + 18], fill=BONE)
    return im


# 1. idle prompt
for _ in range(8):
    frames.append(render([], cursor=True))

# 2. type command 1, 3 chars per frame
lines = [("cmd", CMD1, 0)]
for n in range(0, len(CMD1) + 1, 3):
    lines = [("cmd", CMD1, min(n, len(CMD1)))]
    frames.append(render(lines, cursor=False))
frames.append(render([("cmd", CMD1, len(CMD1))], cursor=True))
for _ in range(6):
    frames.append(render([("cmd", CMD1, len(CMD1))], cursor=True))

# 3. probe output
frames.append(render([("cmd", CMD1, len(CMD1)), ("out", OUT1[0][0], OUT1[0][1])], cursor=True))
for _ in range(10):
    frames.append(render([("cmd", CMD1, len(CMD1)), ("out", OUT1[0][0], OUT1[0][1])], cursor=True))

# 4. type command 2
base_lines = [("cmd", CMD1, len(CMD1)), ("out", OUT1[0][0], OUT1[0][1])]
for n in range(0, len(CMD2) + 1, 3):
    frames.append(render(base_lines + [("cmd", CMD2, min(n, len(CMD2)))], cursor=False))
frames.append(render(base_lines + [("cmd", CMD2, len(CMD2))], cursor=True))
for _ in range(5):
    frames.append(render(base_lines + [("cmd", CMD2, len(CMD2))], cursor=True))

# 5. exploit output, one line every two frames
acc = base_lines + [("cmd", CMD2, len(CMD2))]
for text, col in OUT2:
    acc = acc + [("out", text, col)]
    frames.append(render(acc, cursor=True))
    frames.append(render(acc, cursor=True))

# 6. hold with a blinking cursor
for i in range(40):
    frames.append(render(acc, cursor=(i // 6) % 2 == 0))

# save with a global palette
flat = frames[-1].quantize(colors=48, method=Image.MEDIANCUT)
pal_frames = [im.quantize(palette=flat, dither=Image.NONE) for im in frames]
pal_frames[0].save(
    "assets/demo.gif",
    save_all=True,
    append_images=pal_frames[1:],
    duration=FRAME,
    loop=0,
    optimize=True,
    disposal=2,
)
print("frames", len(frames), "->", "assets/demo.gif")
