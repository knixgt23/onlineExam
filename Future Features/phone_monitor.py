"""
Enhanced side camera monitor with sophisticated object detection
Detects: phones, books, laptops, writing materials, unauthorized devices
Includes calculator whitelisting and smart alert system
"""

import cv2 as cv
import numpy as np
from datetime import datetime
import time
from ultralytics import YOLO

# ---------- CONFIG ----------
YOLO_INTERVAL = 3          # Check every 3 seconds (more frequent)
YOLO_CONF = 0.25           # Lower confidence for better detection
CALCULATOR_IMAGE = None
WHITELIST_FEATURES = None

# Prohibited items mapping
PROHIBITED_ITEMS = {
    'cell phone': 'Mobile Phone',
    'book': 'Book/Notes',
    'laptop': 'Laptop',
    'keyboard': 'External Keyboard',
    'mouse': 'Mouse',
    'remote': 'Electronic Device',
    'tablet': 'Tablet',
    'tv': 'Monitor/Screen'
}

# Load YOLO
model = YOLO("yolov8n.pt")

# --- Detection state ---
last_status = ""
violation_count = {}
last_alert_time = {}

def mark_status(s):
    global last_status
    if s != last_status:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {s}")
        last_status = s

def whitelist_calculator():
    """Sophisticated calculator whitelisting with feature extraction"""
    print("\n" + "="*50)
    print("🔒 CALCULATOR WHITELISTING")
    print("="*50)
    print("Hold your calculator clearly in front of the SIDE camera")
    print("Press 's' to save, 'q' to skip")
    
    cap = cv.VideoCapture(0)
    
    while True:
        ret, frame = cap.read()
        if not ret:
            print("Cannot access camera")
            break
        
        # Draw guide box
        h, w = frame.shape[:2]
        cv.rectangle(frame, (w//4, h//4), (3*w//4, 3*h//4), (0, 255, 0), 2)
        cv.putText(frame, "Position calculator in green box", 
                   (10, 30), cv.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        cv.putText(frame, "Press 's' to save | 'q' to skip", 
                   (10, 60), cv.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
        
        cv.imshow("Whitelist Calculator", frame)
        
        key = cv.waitKey(1) & 0xFF
        if key == ord('s'):
            global CALCULATOR_IMAGE, WHITELIST_FEATURES
            CALCULATOR_IMAGE = frame.copy()
            
            # Extract features for better matching
            gray = cv.cvtColor(frame, cv.COLOR_BGR2GRAY)
            WHITELIST_FEATURES = {
                'size': (frame.shape[0], frame.shape[1]),
                'edges': cv.Canny(gray, 50, 150),
                'hist': cv.calcHist([gray], [0], None, [256], [0, 256])
            }
            print("✓ Calculator whitelisted successfully!")
            break
        elif key == ord('q'):
            print("Skipped whitelisting")
            break
    
    cap.release()
    cv.destroyAllWindows()
    time.sleep(1)

def is_whitelisted_object(frame, box):
    """Advanced matching using multiple features"""
    if CALCULATOR_IMAGE is None or WHITELIST_FEATURES is None:
        return False
    
    try:
        x1, y1, x2, y2 = map(int, box.xyxy[0])
        x1, y1 = max(0, x1), max(0, y1)
        x2, y2 = min(frame.shape[1], x2), min(frame.shape[0], y2)
        
        detected = frame[y1:y2, x1:x2]
        if detected.size == 0 or detected.shape[0] < 20 or detected.shape[1] < 20:
            return False
        
        det_gray = cv.cvtColor(detected, cv.COLOR_BGR2GRAY)
        
        # Size similarity
        size_ratio = min(detected.shape[0]/WHITELIST_FEATURES['size'][0],
                        detected.shape[1]/WHITELIST_FEATURES['size'][1])
        if size_ratio < 0.3 or size_ratio > 3.0:
            return False
        
        # Histogram comparison
        det_hist = cv.calcHist([det_gray], [0], None, [256], [0, 256])
        hist_similarity = cv.compareHist(WHITELIST_FEATURES['hist'], det_hist, cv.HISTCMP_CORREL)
        
        return hist_similarity > 0.5  # 50% similarity threshold
    except:
        return False

def should_alert(item_type):
    """Smart alerting to avoid spam"""
    global last_alert_time
    now = time.time()
    
    # Alert only if 10+ seconds passed since last alert for this item
    if item_type in last_alert_time:
        if now - last_alert_time[item_type] < 10:
            return False
    
    last_alert_time[item_type] = now
    return True

def analyze_hand_movements(frame, prev_frame):
    """Detect suspicious hand movements (writing, typing gestures)"""
    if prev_frame is None:
        return False
    
    # Optical flow to detect hand movement patterns
    gray1 = cv.cvtColor(prev_frame, cv.COLOR_BGR2GRAY)
    gray2 = cv.cvtColor(frame, cv.COLOR_BGR2GRAY)
    
    flow = cv.calcOpticalFlowFarneback(gray1, gray2, None, 0.5, 3, 15, 3, 5, 1.2, 0)
    mag, _ = cv.cartToPolar(flow[..., 0], flow[..., 1])
    
    # High magnitude in lower portion = possible writing/typing
    lower_region = mag[int(mag.shape[0]*0.6):, :]
    avg_motion = np.mean(lower_region)
    
    return avg_motion > 2.5  # Threshold for suspicious hand activity

def monitor_live_camera():
    """Monitor phone camera in real-time"""
    print("\n" + "="*50)
    print("📹 LIVE SIDE CAMERA MONITORING")
    print("="*50)
    print("Press 'q' to stop\n")
    
    cap = cv.VideoCapture(0)
    last_yolo_time = 0
    prev_frame = None
    writing_detected_count = 0
    
    while True:
        ret, frame = cap.read()
        if not ret:
            print("Cannot access camera")
            break
        
        display_frame = frame.copy()
        
        # Run YOLO detection
        if time.time() - last_yolo_time >= YOLO_INTERVAL:
            last_yolo_time = time.time()
            
            try:
                results = model.predict(frame, conf=YOLO_CONF, verbose=False)
                detected = []
                
                for box in results[0].boxes:
                    cls_id = int(box.cls[0])
                    label = model.names[cls_id]
                    
                    if label in PROHIBITED_ITEMS:
                        # Check whitelist
                        if not is_whitelisted_object(frame, box):
                            item_name = PROHIBITED_ITEMS[label]
                            detected.append(item_name)
                            
                            # Track violations
                            violation_count[item_name] = violation_count.get(item_name, 0) + 1
                            
                            # Draw bounding box
                            x1, y1, x2, y2 = map(int, box.xyxy[0])
                            cv.rectangle(display_frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                            cv.putText(display_frame, item_name, (x1, y1-10),
                                     cv.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
                            
                            # Smart alerting
                            if should_alert(item_name):
                                mark_status(f"🚨 VIOLATION: {item_name} detected!")
                
                if detected:
                    status_msg = "⚠️ SUSPICIOUS: " + ", ".join(set(detected))
                    mark_status(status_msg)
                else:
                    mark_status("✓ Clear - No violations")
                    
            except Exception as e:
                print(f"⚠️ Detection error: {e}")
        
        # Hand movement analysis
        if prev_frame is not None and time.time() - last_yolo_time > 1:
            if analyze_hand_movements(frame, prev_frame):
                writing_detected_count += 1
                if writing_detected_count > 3:  # Confirm pattern
                    mark_status("⚠️ SUSPICIOUS: Writing/typing motion detected")
                    writing_detected_count = 0
            else:
                writing_detected_count = max(0, writing_detected_count - 1)
        
        prev_frame = frame.copy()
        
        # Display violation summary
        if violation_count:
            y_offset = 30
            for item, count in violation_count.items():
                cv.putText(display_frame, f"{item}: {count}x", (10, y_offset),
                         cv.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)
                y_offset += 25
        
        cv.imshow("Side Camera Monitor (press 'q' to quit)", display_frame)
        
        if cv.waitKey(1) & 0xFF == ord('q'):
            break
    
    cap.release()
    cv.destroyAllWindows()
    
    # Print final report
    print("\n" + "="*50)
    print("📊 MONITORING SESSION SUMMARY")
    print("="*50)
    if violation_count:
        for item, count in violation_count.items():
            print(f"  • {item}: {count} violation(s)")
    else:
        print("  ✓ No violations detected")

if __name__ == '__main__':
    print("\n📱 ENHANCED SIDE CAMERA MONITOR\n")
    
    # Optional calculator whitelisting
    choice = input("Whitelist calculator before exam? (y/n): ").lower()
    if choice == 'y':
        whitelist_calculator()
    
    # Start monitoring
    monitor_live_camera()
    
    print("\nMonitoring stopped.")