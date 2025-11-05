"""
Laptop server for online exam anti-cheating
- Shows QR code / ngrok link for phone
- Receives phone feed
- Displays live feed + sophisticated cheating detection
- Sends alerts to student's browser
"""

from flask import Flask, render_template_string, Response, request, jsonify
import qrcode
import io
import time
import cv2 as cv
import numpy as np

app = Flask(__name__)

# ---------------- CONFIG ----------------
NGROK_URL = "https://nonadjacent-unenquired-genesis.ngrok-free.dev/phone"
latest_frame = None
last_frame_time = time.time()
last_frame_gray = None
alert_queue = []  # Store alerts to send to student

# Load Haar cascade for face detection
face_cascade = cv.CascadeClassifier(cv.data.haarcascades + "haarcascade_frontalface_default.xml")

# Suspicious activity counters
activity_log = {
    'no_face': 0,
    'multiple_faces': 0,
    'excessive_movement': 0,
    'looking_away': 0
}

# ---------------- HTML ----------------
LAPTOP_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Exam Monitor - Laptop</title></head>
<body style="text-align:center; font-family:Arial; padding:20px;">
    <h2>Secondary Camera Setup</h2>
    <p>Scan this QR code with your phone:</p>
    <img src="/qr" style="width:300px; height:300px; border:2px solid #333;">

    <h3>Live Side Camera Feed</h3>
    <img src="/stream" style="width:640px; border:2px solid #333;">
    
    <br><br>
    <div id="status" style="font-size:18px; color:#666;">Waiting for phone connection...</div>
    
    <div style="margin-top:20px; padding:15px; background:#f5f5f5; border-radius:8px;">
        <h4>Activity Log</h4>
        <div id="activity" style="text-align:left; max-width:600px; margin:0 auto; font-size:14px;"></div>
    </div>
    
    <script>
        setInterval(() => {
            fetch('/status')
                .then(r => r.json())
                .then(data => {
                    let txt = data.connected ? "✓ Phone Connected | " + data.suspicious : "Waiting for phone connection...";
                    let color = data.connected ? "green" : "#666";
                    document.getElementById('status').textContent = txt;
                    document.getElementById('status').style.color = color;
                    
                    // Update activity log
                    let log = data.activity_log || {};
                    let html = '';
                    for (let key in log) {
                        if (log[key] > 0) {
                            html += `<div>• ${key.replace(/_/g, ' ')}: ${log[key]} times</div>`;
                        }
                    }
                    document.getElementById('activity').innerHTML = html || 'No suspicious activity detected';
                });
        }, 2000);
    </script>
</body>
</html>
"""

PHONE_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Side Camera - Exam Monitor</title>
    <style>
        .alert-box {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: #ff4444;
            color: white;
            padding: 20px 30px;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            z-index: 1000;
            display: none;
            animation: shake 0.5s;
        }
        @keyframes shake {
            0%, 100% { transform: translateX(-50%) rotate(0deg); }
            25% { transform: translateX(-50%) rotate(-5deg); }
            75% { transform: translateX(-50%) rotate(5deg); }
        }
    </style>
</head>
<body style="margin:0; background:#000; font-family:Arial;">
    <div id="alert" class="alert-box"></div>
    
    <div style="text-align:center; color:white; padding:10px;">
        <h3>🎥 Side Camera Active</h3>
        <div id="status">Starting camera...</div>
    </div>
    <video id="video" autoplay playsinline style="width:100%; max-width:640px; display:block; margin:0 auto;"></video>
    
    <script>
        const video = document.getElementById('video');
        const status = document.getElementById('status');
        const alertBox = document.getElementById('alert');

        navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
        .then(stream => {
            video.srcObject = stream;
            status.textContent = '✓ Monitoring Active';
            
            // Send frames
            setInterval(() => {
                const canvas = document.createElement('canvas');
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                canvas.getContext('2d').drawImage(video, 0, 0);
                
                canvas.toBlob(blob => {
                    const formData = new FormData();
                    formData.append('frame', blob);
                    fetch('/upload', { method: 'POST', body: formData }).catch(()=>{});
                }, 'image/jpeg', 0.5);
            }, 1000);
            
            // Check for alerts
            setInterval(() => {
                fetch('/get_alerts')
                    .then(r => r.json())
                    .then(data => {
                        if (data.alert) {
                            showAlert(data.alert);
                        }
                    });
            }, 2000);
        })
        .catch(err => {
            status.textContent = '✗ Camera access denied';
            alert('Please allow camera access!');
        });
        
        function showAlert(message) {
            alertBox.textContent = '⚠️ ' + message;
            alertBox.style.display = 'block';
            
            // Vibrate if supported
            if (navigator.vibrate) {
                navigator.vibrate([200, 100, 200]);
            }
            
            setTimeout(() => {
                alertBox.style.display = 'none';
            }, 5000);
        }
    </script>
</body>
</html>
"""

# ---------------- ROUTES ----------------
@app.route('/')
def laptop_page():
    return render_template_string(LAPTOP_PAGE)

@app.route('/phone')
def phone_page():
    return render_template_string(PHONE_PAGE)

@app.route('/qr')
def generate_qr():
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(NGROK_URL)
    qr.make()
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return Response(buf, mimetype='image/png')

@app.route('/upload', methods=['POST'])
def upload():
    global latest_frame, last_frame_time
    if 'frame' in request.files:
        latest_frame = request.files['frame'].read()
        last_frame_time = time.time()
    return 'OK'

@app.route('/get_alerts')
def get_alerts():
    """Send alerts to student's phone"""
    if alert_queue:
        alert = alert_queue.pop(0)
        return jsonify({'alert': alert})
    return jsonify({'alert': None})

# ---------------- SOPHISTICATED DETECTION ----------------
SUSPICIOUS_MSG = ""
consecutive_violations = 0

def send_alert(message):
    """Add alert to queue for student"""
    alert_queue.append(message)

def check_suspicious(frame_bytes):
    global last_frame_gray, SUSPICIOUS_MSG, consecutive_violations
    nparr = np.frombuffer(frame_bytes, np.uint8)
    frame = cv.imdecode(nparr, cv.IMREAD_COLOR)
    
    if frame is None:
        return "Error processing frame"
    
    gray = cv.cvtColor(frame, cv.COLOR_BGR2GRAY)
    violations = []
    
    # 1️⃣ Face detection
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(60,60))
    if len(faces) == 0:
        violations.append("No face detected")
        activity_log['no_face'] += 1
        if activity_log['no_face'] % 3 == 0:  # Alert every 3rd violation
            send_alert("⚠️ ALERT: Keep your face visible!")
    elif len(faces) > 1:
        violations.append("Multiple faces")
        activity_log['multiple_faces'] += 1
        send_alert("⚠️ ALERT: Multiple people detected!")
    else:
        violations.append("✓ Face visible")
    
    # 2️⃣ Excessive movement detection
    if last_frame_gray is not None:
        diff = cv.absdiff(last_frame_gray, gray)
        non_zero = np.count_nonzero(diff > 30)
        
        if non_zero > 150000:  # High movement threshold
            violations.append("⚠️ Excessive movement")
            activity_log['excessive_movement'] += 1
            if activity_log['excessive_movement'] % 5 == 0:
                send_alert("⚠️ ALERT: Reduce movement - stay focused!")
    
    # 3️⃣ Looking away detection (head pose estimation via face position)
    if len(faces) == 1:
        x, y, w, h = faces[0]
        frame_center_x = frame.shape[1] // 2
        face_center_x = x + w // 2
        
        # If face is significantly off-center
        if abs(face_center_x - frame_center_x) > frame.shape[1] * 0.3:
            violations.append("⚠️ Looking away")
            activity_log['looking_away'] += 1
            if activity_log['looking_away'] % 4 == 0:
                send_alert("⚠️ ALERT: Face your exam screen!")
    
    # 4️⃣ Edge detection for detecting papers/books on table
    edges = cv.Canny(gray, 50, 150)
    edge_density = np.count_nonzero(edges) / edges.size
    
    if edge_density > 0.15:  # High edge density = possible papers/books
        violations.append("⚠️ Possible materials on table")
    
    last_frame_gray = gray.copy()
    
    # Track consecutive violations
    if any('⚠️' in v for v in violations):
        consecutive_violations += 1
        if consecutive_violations >= 5:
            send_alert("🚨 WARNING: Multiple violations detected! Focus on your exam.")
            consecutive_violations = 0
    else:
        consecutive_violations = max(0, consecutive_violations - 1)
    
    SUSPICIOUS_MSG = " | ".join(violations)
    return SUSPICIOUS_MSG

@app.route('/status')
def status():
    connected = latest_frame is not None
    suspicious = ""
    if connected:
        if time.time() - last_frame_time > 5:
            connected = False
            suspicious = "⚠️ Phone feed stopped"
        else:
            suspicious = check_suspicious(latest_frame)
    return jsonify({
        'connected': connected, 
        'suspicious': suspicious,
        'activity_log': activity_log
    })

# ---------------- STREAM ----------------
def gen_frames():
    global latest_frame
    while True:
        if latest_frame is None:
            time.sleep(0.05)
            continue
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + latest_frame + b'\r\n')
        time.sleep(0.05)

@app.route('/stream')
def stream():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

# ---------------- MAIN ----------------
if __name__ == '__main__':
    print(f"\n{'='*50}")
    print(f"📱 ENHANCED EXAM MONITOR SERVER")
    print(f"{'='*50}")
    print(f"\n1. Open browser: http://localhost:5000")
    print(f"2. Scan QR code on phone")
    print(f"3. Student will receive real-time alerts for violations")
    print(f"\nDetection features:")
    print(f"  ✓ Face visibility monitoring")
    print(f"  ✓ Multiple person detection")
    print(f"  ✓ Excessive movement alerts")
    print(f"  ✓ Looking away detection")
    print(f"  ✓ Material detection on table")
    app.run(host='0.0.0.0', port=5000, debug=False)