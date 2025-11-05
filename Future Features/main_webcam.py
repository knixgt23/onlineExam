"""
Enhanced main webcam anti-cheating with sophisticated detection
Features:
- Face presence & attention monitoring
- Prohibited object detection (phones, books, laptops)
- Eye gaze estimation (looking at screen vs elsewhere)
- Real-time audio alerts for violations (non-blocking)
"""

import cv2 as cv
from datetime import datetime
import time
from ultralytics import YOLO
import numpy as np
import threading

try:
    import pyttsx3
    audio_available = True
except:
    audio_available = False
    print("⚠️ pyttsx3 not installed - audio alerts disabled")

# ---------- CONFIG ----------
YOLO_INTERVAL = 4          # seconds between YOLO runs
YOLO_CONF = 0.25           # confidence threshold
ABSENCE_THRESHOLD = 3.0    # seconds of continuous "no face" before alert
LOOKING_AWAY_THRESHOLD = 5.0  # seconds before alerting

# Load YOLO
model = YOLO("yolov8n.pt")

# Load Haar Cascades
face_cascade = cv.CascadeClassifier(cv.data.haarcascades + "haarcascade_frontalface_default.xml")
eye_cascade = cv.CascadeClassifier(cv.data.haarcascades + "haarcascade_eye.xml")

# Initialize text-to-speech (non-blocking)
def speak_alert(message):
    """Speak alert in separate thread to avoid freezing"""
    if audio_available:
        def _speak():
            try:
                engine = pyttsx3.init()
                engine.setProperty('rate', 150)
                engine.setProperty('volume', 0.9)
                engine.say(message)
                engine.runAndWait()
                engine.stop()
            except:
                pass
        threading.Thread(target=_speak, daemon=True).start()

# Webcam setup
cap = cv.VideoCapture(0)
cap.set(cv.CAP_PROP_FRAME_WIDTH, 800)
cap.set(cv.CAP_PROP_FRAME_HEIGHT, 600)

print("🎓 Enhanced Anti-Cheating Monitor Started")
print("Press 'q' to quit\n")

# --- Status trackers ---
last_status = ""
last_yolo_time = 0
no_face_start = None
looking_away_start = None
violation_log = {}
last_audio_alert = 0

def mark_status(s):
    """Print and optionally speak status updates"""
    global last_status, last_audio_alert
    if s != last_status:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {s}")
        last_status = s
        
        # Audio alert for serious violations (with cooldown to prevent spam)
        if "SUSPICIOUS" in s and time.time() - last_audio_alert > 10:
            last_audio_alert = time.time()
            if "Multiple faces" in s:
                speak_alert("Warning: Multiple people detected")
            elif "No face" in s:
                speak_alert("Warning: Face not visible")
            elif "Objects" in s:
                speak_alert("Warning: Prohibited items detected")

def detect_eye_gaze(face_roi, gray_roi):
    """Estimate if student is looking at screen or away"""
    eyes = eye_cascade.detectMultiScale(gray_roi, scaleFactor=1.1, minNeighbors=10, minSize=(20,20))
    
    if len(eyes) < 2:
        return "looking_away"
    
    # Check eye position relative to face
    face_width = face_roi[2]
    eye_positions = [x + w//2 for (x, y, w, h) in eyes]
    
    # If eyes are too far to the side, student is looking away
    for eye_x in eye_positions:
        if eye_x < face_width * 0.2 or eye_x > face_width * 0.8:
            return "looking_away"
    
    return "looking_forward"

while True:
    ret, frame = cap.read()
    if not ret:
        print("Webcam not accessible")
        break

    gray = cv.cvtColor(frame, cv.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(60,60))
    now = time.time()
    
    current_warnings = []

    # ---------- Face & Attention Detection ----------
    if len(faces) == 0:
        if no_face_start is None:
            no_face_start = now
        
        if now - no_face_start >= ABSENCE_THRESHOLD:
            current_warnings.append("No face detected")
            violation_log['no_face'] = violation_log.get('no_face', 0) + 1
        
        looking_away_start = None
        
    elif len(faces) > 1:
        current_warnings.append("Multiple faces detected")
        violation_log['multiple_faces'] = violation_log.get('multiple_faces', 0) + 1
        no_face_start = None
        looking_away_start = None
        
    else:
        no_face_start = None
        x, y, w, h = faces[0]
        
        # Draw face rectangle
        cv.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
        
        face_roi = (x, y, w, h)
        gray_roi = gray[y:y+h, x:x+w]
        
        # Eye gaze detection
        gaze = detect_eye_gaze(face_roi, gray_roi)
        if gaze == "looking_away":
            if looking_away_start is None:
                looking_away_start = now
            elif now - looking_away_start >= LOOKING_AWAY_THRESHOLD:
                current_warnings.append("Looking away from screen")
                violation_log['looking_away'] = violation_log.get('looking_away', 0) + 1
        else:
            looking_away_start = None

    # ---------- YOLO Object Detection ----------
    if time.time() - last_yolo_time >= YOLO_INTERVAL:
        last_yolo_time = time.time()
        
        try:
            results = model.predict(frame, conf=YOLO_CONF, verbose=False)
            detected_items = []
            
            for box in results[0].boxes:
                cls_id = int(box.cls[0])
                label = model.names[cls_id]
                
                if label in ["cell phone", "book", "laptop", "remote", "tv", "keyboard"]:
                    detected_items.append(label)
                    violation_log[label] = violation_log.get(label, 0) + 1
                    
                    # Draw bounding box
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    cv.rectangle(frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                    cv.putText(frame, label.upper(), (x1, y1-10),
                             cv.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)
            
            if detected_items:
                current_warnings.append(f"Objects: {', '.join(set(detected_items))}")
                
        except Exception as e:
            print("⚠️ YOLO error:", e)

    # ---------- Status Update ----------
    if current_warnings:
        status = "🚨 SUSPICIOUS: " + " | ".join(current_warnings)
        mark_status(status)
        status_color = (0, 0, 255)  # Red
    else:
        if last_status != "✓ Normal - Monitoring active":
            mark_status("✓ Normal - Monitoring active")
        status_color = (0, 255, 0)  # Green
        current_warnings = ["✓ Normal"]

    # ---------- Display ----------
    # Status text
    y_pos = 30
    for warning in current_warnings:
        cv.putText(frame, warning, (10, y_pos),
                 cv.FONT_HERSHEY_SIMPLEX, 0.7, status_color, 2, cv.LINE_AA)
        y_pos += 30
    
    # Violation summary (top right)
    if violation_log:
        y_pos = 30
        cv.putText(frame, "Violations:", (frame.shape[1] - 200, y_pos),
                 cv.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        y_pos += 25
        
        for violation, count in list(violation_log.items())[:5]:  # Show top 5
            text = f"{violation}: {count}"
            cv.putText(frame, text, (frame.shape[1] - 200, y_pos),
                     cv.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 255), 1)
            y_pos += 20

    cv.imshow("Enhanced Anti-Cheat Monitor (press 'q' to quit)", frame)

    if cv.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv.destroyAllWindows()

# Print final report
print("\n" + "="*50)
print("📊 EXAM MONITORING REPORT")
print("="*50)
if violation_log:
    print("\nViolations detected:")
    for violation, count in sorted(violation_log.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {violation.replace('_', ' ').title()}: {count} time(s)")
else:
    print("\n✓ No violations detected - Clean exam session")
print("\nMonitoring stopped.")