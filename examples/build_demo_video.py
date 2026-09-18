#!/usr/bin/env /usr/bin/python3
"""
VeriFireWall - Master Screen Recording Generator
================================================
Generates a broadcast-quality 92-second demonstration video (1920x1080 @ 24fps)
showcasing:
  1. Platform Architecture & Capabilities
  2. The Target Web Application (OWASP Juice Shop)
  3. Live Cyber Attack Generation (SQLi, XSS, RCE, Path Traversal)
  4. Active WAF Block Interception (HTTP 403 Forbidden with Incident ID)
  5. Live VeriFireWall Dashboard Telemetry with Real-Time Smooth Scroll
  6. Layer 4 Network NIDS (UNSW-NB15 XGBoost ML Model)
  7. Grafana Metrics & Prometheus Observability
  8. Dozzle Container Infrastructure Monitoring
  9. Executive Recap & Defense Metrics
"""

import os, sys, subprocess, math
from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = "/tmp/vfw_demo_assets"
OUTPUT_FILE = "/home/Kritish/Development/verifierwall/verifirewall_demo.mp4"
WIDTH, HEIGHT = 1920, 1080
FPS = 24

FONT_PATH_BOLD = "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"
FONT_PATH_REG = "/usr/share/fonts/TTF/DejaVuSans.ttf"

font_badge = ImageFont.truetype(FONT_PATH_BOLD, 15)
font_title = ImageFont.truetype(FONT_PATH_BOLD, 18)
font_sub = ImageFont.truetype(FONT_PATH_REG, 14)

def draw_lower_third(base_img, badge_text, title_text, stage_num=1, total_stages=9):
    # Make a copy or overlay
    overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    
    # Bottom banner bar
    bar_x1, bar_y1 = 36, HEIGHT - 92
    bar_x2, bar_y2 = WIDTH - 36, HEIGHT - 24
    radius = 12
    
    # Background glass panel
    draw.rounded_rectangle([bar_x1, bar_y1, bar_x2, bar_y2], radius=radius, fill=(15, 23, 42, 238), outline=(51, 65, 85, 255), width=2)
    
    # Pulse dot indicator
    dot_color = (34, 197, 94, 255) if stage_num in [1, 2, 8, 9] else ((239, 68, 68, 255) if stage_num in [3, 4] else (56, 189, 248, 255))
    draw.ellipse([bar_x1 + 18, bar_y1 + 26, bar_x1 + 32, bar_y1 + 40], fill=dot_color)
    
    # Stage pill
    pill_x1 = bar_x1 + 44
    pill_y1 = bar_y1 + 18
    pill_text = f"STAGE {stage_num}/{total_stages} • {badge_text.upper()}"
    pill_bbox = draw.textbbox((0, 0), pill_text, font=font_badge)
    pill_w = pill_bbox[2] - pill_bbox[0] + 20
    draw.rounded_rectangle([pill_x1, pill_y1, pill_x1 + pill_w, pill_y1 + 32], radius=6, fill=(30, 41, 59, 255), outline=(71, 85, 105, 255), width=1)
    draw.text((pill_x1 + 10, pill_y1 + 7), pill_text, font=font_badge, fill=(56, 189, 248, 255))
    
    # Title text
    draw.text((pill_x1 + pill_w + 20, bar_y1 + 23), title_text, font=font_title, fill=(248, 250, 252, 255))
    
    # Composite
    base_rgba = base_img.convert("RGBA")
    combined = Image.alpha_composite(base_rgba, overlay)
    return combined.convert("RGB")

def smooth_scroll(img_tall, scroll_y, crop_w=WIDTH, crop_h=HEIGHT):
    max_y = img_tall.height - crop_h
    y = max(0, min(int(scroll_y), max_y))
    return img_tall.crop((0, y, crop_w, y + crop_h))

def crossfade(img1, img2, alpha):
    return Image.blend(img1, img2, alpha)

def ease_in_out(t):
    return 0.5 * (1 - math.cos(math.pi * t))

def main():
    print("=" * 70)
    print(" 🎬 Generating VeriFireWall Master Screen Recording Video...")
    print("=" * 70)
    
    # Load all base images
    assets = {
        "intro": Image.open(f"{ASSETS_DIR}/01_intro.png").convert("RGB"),
        "juiceshop": Image.open(f"{ASSETS_DIR}/02_juiceshop.png").convert("RGB"),
        "terminal": Image.open(f"{ASSETS_DIR}/03_terminal.png").convert("RGB"),
        "blocked": Image.open(f"{ASSETS_DIR}/04_attack_blocked.png").convert("RGB"),
        "dash_tall": Image.open(f"{ASSETS_DIR}/05_dashboard_tall.png").convert("RGB"),
        "dash_l4": Image.open(f"{ASSETS_DIR}/06_dashboard_l4.png").convert("RGB"),
        "grafana": Image.open(f"{ASSETS_DIR}/07_grafana.png").convert("RGB"),
        "dozzle": Image.open(f"{ASSETS_DIR}/08_dozzle.png").convert("RGB"),
        "recap": Image.open(f"{ASSETS_DIR}/09_recap.png").convert("RGB"),
    }
    
    # Prepare scenes (duration in seconds)
    scenes = [
        {"id": "intro", "dur": 10, "badge": "PLATFORM OVERVIEW", "title": "VeriFireWall: Autonomous AI Web Application & Network Firewall", "stage": 1},
        {"id": "juiceshop", "dur": 10, "badge": "TARGET WEB APP", "title": "OWASP Juice Shop Storefront Protected Behind WAF Reverse Proxy (Port 80)", "stage": 2},
        {"id": "terminal", "dur": 12, "badge": "ATTACK SIMULATION", "title": "Simulating Cyber Attacks: SQLi, XSS, Command Injection, Shellshock RCE & NetFlow Floods", "stage": 3},
        {"id": "blocked", "dur": 10, "badge": "ACTIVE WAF DEFENSE", "title": "Attack Intercepted by ML WAAP Engine — HTTP 403 Forbidden with Check Point Incident ID", "stage": 4},
        {"id": "dash_tall", "dur": 18, "badge": "AI TELEMETRY", "title": "VeriFireWall Telemetry: Live Anomaly Scoring, Attack Breakdown & Incident Stream", "stage": 5, "scroll": True},
        {"id": "dash_l4", "dur": 10, "badge": "LAYER 4 NIDS", "title": "UNSW-NB15 XGBoost Classifier: Sub-Millisecond NetFlow Anomaly Detection (<1.2ms)", "stage": 6},
        {"id": "grafana", "dur": 8, "badge": "METRICS & OBSERVABILITY", "title": "Grafana Dashboard: NGINX Throughput, Prometheus Metrics & WAF Enforcement Stats", "stage": 7},
        {"id": "dozzle", "dur": 6, "badge": "CONTAINER TOPOLOGY", "title": "Microservice Health: Agent, NGINX Proxy, SmartSync & Storage Containers", "stage": 8},
        {"id": "recap", "dur": 8, "badge": "DEFENSE SUMMARY", "title": "Autonomous Threat Protection Accomplished: 100% Zero-Day & OWASP Attack Block Rate", "stage": 9},
    ]
    
    total_duration = sum(s["dur"] for s in scenes)
    total_frames = total_duration * FPS
    print(f"📊 Total Video Duration: {total_duration} seconds ({total_duration/60:.1f} mins) @ {FPS} fps = {total_frames} frames")
    
    # Start ffmpeg rawvideo pipe
    ffmpeg_cmd = [
        "ffmpeg", "-y",
        "-f", "rawvideo",
        "-vcodec", "rawvideo",
        "-s", f"{WIDTH}x{HEIGHT}",
        "-pix_fmt", "rgb24",
        "-r", str(FPS),
        "-i", "-",
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-movflags", "+faststart",
        OUTPUT_FILE
    ]
    
    ffmpeg_proc = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    
    fade_frames = 12 # 0.5s crossfade between scenes
    prev_scene_last_frame = None
    
    frame_count = 0
    
    for s_idx, sc in enumerate(scenes):
        dur_frames = sc["dur"] * FPS
        base_asset = assets[sc["id"]]
        is_scroll = sc.get("scroll", False)
        
        print(f"  🎬 Rendering Scene {s_idx+1}/{len(scenes)}: {sc['badge']} ({sc['dur']}s, {dur_frames} frames)...")
        
        for f in range(dur_frames):
            # Compute base frame image
            if is_scroll:
                # 0..100: hold top; 100..320: smooth scroll down; 320..dur_frames: hold bottom
                hold_top = 100
                hold_bottom = 100
                scroll_span = dur_frames - hold_top - hold_bottom
                
                if f < hold_top:
                    curr_y = 0
                elif f >= hold_top + scroll_span:
                    curr_y = base_asset.height - HEIGHT
                else:
                    progress = (f - hold_top) / float(scroll_span)
                    eased = ease_in_out(progress)
                    curr_y = eased * (base_asset.height - HEIGHT)
                
                frame_img = smooth_scroll(base_asset, curr_y)
            else:
                frame_img = base_asset.copy()
            
            # Draw lower third card
            frame_img = draw_lower_third(frame_img, sc["badge"], sc["title"], stage_num=sc["stage"], total_stages=len(scenes))
            
            # Handle crossfade transition from previous scene
            if prev_scene_last_frame is not None and f < fade_frames:
                alpha = (f + 1) / float(fade_frames)
                frame_img = crossfade(prev_scene_last_frame, frame_img, alpha)
            
            # Pipe frame
            ffmpeg_proc.stdin.write(frame_img.tobytes())
            frame_count += 1
            
            if f == dur_frames - 1:
                prev_scene_last_frame = frame_img
    
    # Close pipe and wait for ffmpeg
    ffmpeg_proc.stdin.close()
    _, stderr = ffmpeg_proc.communicate()
    
    if ffmpeg_proc.returncode != 0:
        print("❌ FFmpeg error:", stderr.decode('utf-8')[-500:])
        return 1
        
    size_mb = os.path.getsize(OUTPUT_FILE) / 1_000_000
    print("\n" + "=" * 70)
    print(" 🎉 Video Generation Succeeded!")
    print(f" 📹 Output: {OUTPUT_FILE}")
    print(f" 📦 File Size: {size_mb:.2f} MB")
    print(f" ⏱️  Duration: {total_duration} seconds (1 min 32 sec)")
    print(f" 🖼️  Resolution: {WIDTH}x{HEIGHT} Full HD @ {FPS} fps")
    print("=" * 70)
    return 0

if __name__ == '__main__':
    sys.exit(main())
