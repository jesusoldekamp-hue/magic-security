#!/usr/bin/env python3
"""
Puente Cloud 24/7 Independiente de la Mac para MagicSecurity.
Se ejecuta en servidores Cloud (GitHub Actions / CloudRelay) y se conecta
directamente a los puertos UPnP permanentes del router de casa (18554 RTSP y 18020 ONVIF)
para que la cámara funcione aunque la Mac esté completamente apagada durante 50+ días.
"""
import base64
import datetime
import hashlib
import http.server
import json
import os
import re
import select
import subprocess
import threading
import time
import urllib.parse
import urllib.request

CAMERA_DDNS_HOST = os.environ.get("CAMERA_DDNS_HOST", "").strip()
CAMERA_PUBLIC_IP_FALLBACK = os.environ.get("CAMERA_PUBLIC_IP", "").strip()
TUNNEL_JSON_URL = os.environ.get(
    "TUNNEL_JSON_URL",
    "https://raw.githubusercontent.com/jesusoldekamp-hue/magic-security/main/tunnel.json",
).strip()
CAMERA_RTSP_PORT = int(os.environ.get("CAMERA_RTSP_PORT", "18554"))
CAMERA_ONVIF_PORT = int(os.environ.get("CAMERA_ONVIF_PORT", "18020"))
CAMERA_USER = os.environ.get("CAMERA_USER", "albertgod53").strip()
CAMERA_PASS = os.environ.get("CAMERA_PASS", "").strip()
MOBILE_TOKEN = os.environ.get("MOBILE_TOKEN", "45BwGjboYxfraNWL").strip()
PORT = int(os.environ.get("PORT", "11988"))

HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
host_lock = threading.Lock()
cached_camera_host = CAMERA_DDNS_HOST or CAMERA_PUBLIC_IP_FALLBACK
cached_host_ts = 0.0

frame_lock = threading.Lock()
latest_jpeg = None
latest_frame_ts = 0.0
invert_tilt = False
invert_pan = False
is_moving = False


def get_active_camera_host(force=False):
    """Resuelve el host/IP pública actual de casa (DDNS > tunnel.json publicIP > secret)."""
    global cached_camera_host, cached_host_ts
    if CAMERA_DDNS_HOST:
        return CAMERA_DDNS_HOST
    now = time.time()
    with host_lock:
        if not force and cached_camera_host and (now - cached_host_ts) < 30.0:
            return cached_camera_host
    fetched_ip = ""
    if TUNNEL_JSON_URL:
        try:
            req = urllib.request.Request(
                f"{TUNNEL_JSON_URL}?ts={int(now)}",
                headers={"Cache-Control": "no-cache", "User-Agent": "MagicSecurityCloud/2.0"},
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                cand = str(data.get("publicIP") or "").strip()
                if cand and HOST_RE.match(cand):
                    fetched_ip = cand
        except Exception:
            pass
    with host_lock:
        if fetched_ip:
            if fetched_ip != cached_camera_host:
                print(f"MagicSecurity Cloud Bridge: active home IP updated -> {fetched_ip}", flush=True)
            cached_camera_host = fetched_ip
        elif not cached_camera_host and CAMERA_PUBLIC_IP_FALLBACK:
            cached_camera_host = CAMERA_PUBLIC_IP_FALLBACK
        cached_host_ts = now
        return cached_camera_host


def capture_loop():
    """Mantiene un hilo ligero de captura RTSP desde el router de casa hacia memoria."""
    global latest_jpeg, latest_frame_ts
    user_enc = urllib.parse.quote(CAMERA_USER.split("@")[0], safe="")
    pass_enc = urllib.parse.quote(CAMERA_PASS, safe="")
    while True:
        host = get_active_camera_host(force=True)
        if not host or not CAMERA_PASS:
            time.sleep(5.0)
            continue
        for stream_path in ["stream2", "stream1"]:
            host = get_active_camera_host(force=True)
            if not host:
                break
            rtsp_url = f"rtsp://{user_enc}:{pass_enc}@{host}:{CAMERA_RTSP_PORT}/{stream_path}"
            cmd = [
                "ffmpeg", "-hide_banner", "-loglevel", "error",
                "-rtsp_transport", "tcp",
                "-fflags", "+nobuffer+discardcorrupt",
                "-flags", "low_delay",
                "-i", rtsp_url,
                "-vf", "scale=960:-1",
                "-r", "10",
                "-f", "image2pipe",
                "-vcodec", "mjpeg",
                "-q:v", "5",
                "pipe:1"
            ]
            proc = None
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
                fd = proc.stdout.fileno()
                buf = bytearray()
                last_read = time.time()
                while proc.poll() is None:
                    ready, _, _ = select.select([fd], [], [], 2.0)
                    if not ready:
                        if time.time() - last_read > 12.0:
                            break
                        continue
                    chunk = os.read(fd, 16384)
                    if not chunk:
                        break
                    last_read = time.time()
                    buf.extend(chunk)
                    while True:
                        soi = buf.find(b"\xff\xd8")
                        if soi < 0:
                            buf.clear()
                            break
                        eoi = buf.find(b"\xff\xd9", soi + 2)
                        if eoi < 0:
                            if soi > 0:
                                del buf[:soi]
                            if len(buf) > 2_000_000:
                                buf.clear()
                            break
                        frame = bytes(buf[soi:eoi + 2])
                        del buf[:eoi + 2]
                        with frame_lock:
                            latest_jpeg = frame
                            latest_frame_ts = time.time()
            except Exception:
                pass
            finally:
                if proc is not None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=1.5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
        time.sleep(2.0)


def make_onvif_envelope(user, pw, body_xml):
    nonce = os.urandom(16)
    created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + pw.encode()).digest()).decode()
    nb64 = base64.b64encode(nonce).decode()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{user}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nb64}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">{body_xml}</s:Body>
</s:Envelope>"""


def send_onvif(op, body_xml):
    host = get_active_camera_host()
    if not host or not CAMERA_PASS:
        return False
    short_user = CAMERA_USER.split("@")[0]
    for candidate in [short_user, CAMERA_USER, "admin"]:
        xml = make_onvif_envelope(candidate, CAMERA_PASS, body_xml)
        req = urllib.request.Request(
            f"http://{host}:{CAMERA_ONVIF_PORT}/onvif/ptz_service",
            data=xml.encode(),
            headers={
                "Host": f"{host}:{CAMERA_ONVIF_PORT}",
                "Content-Type": f"application/soap+xml; charset=utf-8; action=\"http://www.onvif.org/ver20/ptz/wsdl/{op}\""
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as r:
                resp_text = r.read().decode(errors="ignore")
                if 200 <= r.status < 300 and ":Fault>" not in resp_text and "<Fault>" not in resp_text:
                    return True
        except Exception:
            continue
    return False


VECTORS = {
    "up": (0.0, 0.6), "down": (0.0, -0.6), "left": (-0.6, 0.0), "right": (0.6, 0.0),
    "upleft": (-0.45, 0.45), "upright": (0.45, 0.45), "downleft": (-0.45, -0.45), "downright": (0.45, -0.45)
}
STEPS = {
    "up": (0.0, 0.08), "down": (0.0, -0.08), "left": (-0.08, 0.0), "right": (0.08, 0.0),
    "upleft": (-0.06, 0.06), "upright": (0.06, 0.06), "downleft": (-0.06, -0.06), "downright": (0.06, -0.06)
}


def execute_ptz(action, direction, speed):
    global invert_tilt, invert_pan, is_moving
    pan_mult = 1.0 if invert_pan else -1.0
    tilt_mult = -1.0 if invert_tilt else 1.0

    if action == "invert_tilt":
        invert_tilt = not invert_tilt
        return True
    if action == "invert_pan":
        invert_pan = not invert_pan
        return True
    if action == "stop" or direction == "stop":
        is_moving = False
        body = """<tptz:Stop xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"><tptz:ProfileToken>profile_1</tptz:ProfileToken><tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>"""
        return send_onvif("Stop", body)
    if action == "preset" or direction in ("p1", "p2", "p3", "1", "2", "3"):
        num = direction.replace("p", "")
        body = f"""<tptz:GotoPreset xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"><tptz:ProfileToken>profile_1</tptz:ProfileToken><tptz:PresetToken>{num}</tptz:PresetToken></tptz:GotoPreset>"""
        return send_onvif("GotoPreset", body)

    d_clean = direction.replace("-", "").replace("_", "")
    if d_clean not in VECTORS:
        return False

    if action == "start":
        vx, vy = VECTORS[d_clean]
        vx = max(-1.0, min(1.0, vx * speed * pan_mult))
        vy = max(-1.0, min(1.0, vy * speed * tilt_mult))
        is_moving = True
        body = f"""<tptz:ContinuousMove xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tptz:ProfileToken>profile_1</tptz:ProfileToken><tptz:Velocity><tt:PanTilt x="{vx:.2f}" y="{vy:.2f}" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"/></tptz:Velocity></tptz:ContinuousMove>"""
        return send_onvif("ContinuousMove", body)

    # nudge
    sx, sy = STEPS[d_clean]
    scale = max(0.5, min(2.5, speed)) * 1.75
    dx = max(-1.0, min(1.0, sx * scale * pan_mult))
    dy = max(-1.0, min(1.0, -sy * scale * tilt_mult))
    body = f"""<tptz:RelativeMove xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><tptz:ProfileToken>profile_1</tptz:ProfileToken><tptz:Translation><tt:PanTilt x="{dx:.3f}" y="{dy:.3f}" space="http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"/></tptz:Translation></tptz:RelativeMove>"""
    return send_onvif("RelativeMove", body)


class CloudHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_cors_headers(self, status, content_type, length):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Mobile-Token")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_cors_headers(204, "text/plain", 0)

    def check_auth(self, parsed):
        qs = urllib.parse.parse_qs(parsed.query)
        t = (qs.get("t", [""])[0]).strip()
        ht = (self.headers.get("X-Mobile-Token") or "").strip()
        return t == MOBILE_TOKEN or ht == MOBILE_TOKEN

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/ping":
            with frame_lock:
                has_frame = latest_jpeg is not None and (time.time() - latest_frame_ts) < 25
            data = json.dumps({"alive": True, "cloud": True, "hasFrame": has_frame}).encode()
            self.send_cors_headers(200, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)
            return

        if not self.check_auth(parsed):
            msg = b"Forbidden"
            self.send_cors_headers(403, "text/plain", len(msg))
            self.wfile.write(msg)
            return

        if parsed.path == "/frame.jpg":
            with frame_lock:
                fresh = latest_jpeg is not None and (time.time() - latest_frame_ts) < 25
                jpg = latest_jpeg if fresh else None
            if not jpg:
                msg = b"Conectando..."
                self.send_cors_headers(503, "text/plain", len(msg))
                self.wfile.write(msg)
                return
            self.send_cors_headers(200, "image/jpeg", len(jpg))
            self.wfile.write(jpg)
            return

        if parsed.path == "/api/status":
            host = get_active_camera_host()
            with frame_lock:
                live = latest_jpeg is not None and (time.time() - latest_frame_ts) < 15
            payload = {
                "cameraName": "Tapo C520WS",
                "isLive": live,
                "fps": 10 if live else 0,
                "isMoving": is_moving,
                "ptzStatus": "",
                "isSirenActive": False,
                "invertTilt": invert_tilt,
                "invertPan": invert_pan,
                "routeText": f"En vivo · Cloud 24/7 ({host})",
                "remoteHost": host
            }
            data = json.dumps(payload).encode()
            self.send_cors_headers(200, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)
            return

        self.send_cors_headers(404, "text/plain", 0)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if not self.check_auth(parsed):
            self.send_cors_headers(403, "text/plain", 0)
            return
        qs = urllib.parse.parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or "0")
        body_json = {}
        if length > 0:
            try:
                body_json = json.loads(self.rfile.read(length).decode())
            except Exception:
                pass

        def param(name, default=""):
            if name in qs and qs[name]:
                return str(qs[name][0])
            if name in body_json:
                return str(body_json[name])
            return default

        if parsed.path == "/api/ptz":
            action = param("action", "nudge").lower()
            direction = param("dir", "").lower()
            try:
                speed = float(param("speed", "1.0"))
            except Exception:
                speed = 1.0
            ok = execute_ptz(action, direction, speed)
            data = json.dumps({
                "ok": ok,
                "invertTilt": invert_tilt,
                "invertPan": invert_pan,
                "isMoving": is_moving,
                "status": ""
            }).encode()
            self.send_cors_headers(200, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)
            return

        data = json.dumps({"ok": True, "isSirenActive": False}).encode()
        self.send_cors_headers(200, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)


if __name__ == "__main__":
    t = threading.Thread(target=capture_loop, daemon=True)
    t.start()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), CloudHandler)
    print(f"MagicSecurity Cloud Bridge listening on 127.0.0.1:{PORT} -> {get_active_camera_host()}:{CAMERA_RTSP_PORT}/{CAMERA_ONVIF_PORT}", flush=True)
    srv.serve_forever()
