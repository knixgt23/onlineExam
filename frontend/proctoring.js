<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proctoring Module</title>
    <script src="https://cdn.jsdelivr.net/npm/@tensorflow/tfjs"></script>
    <script src="https://cdn.jsdelivr.net/npm/@tensorflow-models/coco-ssd"></script>
    <script src="https://cdn.jsdelivr.net/npm/@tensorflow-models/blazeface"></script>
</head>
<body>
<script>
/**
 * Browser-Based Proctoring System
 * This module can be included in your exam-setup.html and exam-page.html
 *
 * Features:
 * - Face detection (no face, multiple faces)
 * - Object detection (phone, laptop, book)
 * - Tab switch detection
 * - Full screen exit detection
 * - Logs events to backend
 */

class ExamProctoring {
    constructor(sessionId, apiBase = 'http://localhost:5000/api') {
        this.sessionId = sessionId;
        this.apiBase = apiBase;
        this.token = localStorage.getItem('authToken');

        // Models
        this.faceModel = null;
        this.objectModel = null;

        // Video streams
        this.cameraStream = null;
        this.videoElement = null;

        // Detection settings
        this.faceCheckInterval = 3000; // Check every 3 seconds
        this.objectCheckInterval = 5000; // Check every 5 seconds
        this.noFaceThreshold = 3000; // Alert after 3 seconds of no face

        // Status tracking
        this.lastFaceDetectionTime = Date.now();
        this.noFaceStartTime = null;
        this.suspiciousEvents = [];
        this.isMonitoring = false;

        // Intervals
        this.faceCheckTimer = null;
        this.objectCheckTimer = null;
        this.eventLogTimer = null;
    }

    /**
     * Initialize proctoring system
     */
    async initialize(videoElementId) {
        console.log('🔍 Initializing proctoring system...');

        try {
            // Get video element
            this.videoElement = document.getElementById(videoElementId);
            if (!this.videoElement) {
                throw new Error('Video element not found');
            }

            // Get camera stream
            this.cameraStream = await navigator.mediaDevices.getUserMedia({
                video: { width: 640, height: 480 }
            });
            this.videoElement.srcObject = this.cameraStream;

            // Load AI models
            console.log('📦 Loading AI models...');
            this.faceModel = await blazeface.load();
            this.objectModel = await cocoSsd.load();
            console.log('✅ Models loaded successfully');

            // Setup fullscreen and visibility detection
            this.setupFullscreenDetection();
            this.setupVisibilityDetection();
            this.setupTabSwitchDetection();

            return true;
        } catch (error) {
            console.error('❌ Failed to initialize proctoring:', error);
            this.logEvent('INITIALIZATION_FAILED', error.message, 'HIGH');
            return false;
        }
    }

    /**
     * Start monitoring
     */
    startMonitoring() {
        if (this.isMonitoring) return;

        console.log('👁️ Starting proctoring monitoring...');
        this.isMonitoring = true;

        // Start face detection
        this.faceCheckTimer = setInterval(() => {
            this.checkFacePresence();
        }, this.faceCheckInterval);

        // Start object detection
        this.objectCheckTimer = setInterval(() => {
            this.checkProhibitedObjects();
        }, this.objectCheckInterval);

        // Batch log events every 10 seconds
        this.eventLogTimer = setInterval(() => {
            this.flushEventLog();
        }, 10000);

        console.log('✅ Proctoring monitoring started');
    }

    /**
     * Stop monitoring
     */
    stopMonitoring() {
        console.log('🛑 Stopping proctoring monitoring...');
        this.isMonitoring = false;

        if (this.faceCheckTimer) clearInterval(this.faceCheckTimer);
        if (this.objectCheckTimer) clearInterval(this.objectCheckTimer);
        if (this.eventLogTimer) clearInterval(this.eventLogTimer);

        // Flush any remaining events
        this.flushEventLog();

        console.log('✅ Proctoring monitoring stopped');
    }

    /**
     * Check for face presence
     */
    async checkFacePresence() {
        if (!this.videoElement || !this.faceModel) return;

        try {
            const predictions = await this.faceModel.estimateFaces(this.videoElement, false);

            if (predictions.length === 0) {
                // No face detected
                if (this.noFaceStartTime === null) {
                    this.noFaceStartTime = Date.now();
                }

                const noFaceDuration = Date.now() - this.noFaceStartTime;
                if (noFaceDuration >= this.noFaceThreshold) {
                    this.logEvent('NO_FACE_DETECTED',
                        `No face detected for ${Math.round(noFaceDuration / 1000)} seconds`,
                        'HIGH');
                }
            } else if (predictions.length > 1) {
                // Multiple faces detected
                this.noFaceStartTime = null;
                this.logEvent('MULTIPLE_FACES',
                    `${predictions.length} faces detected`,
                    'HIGH');
            } else {
                // Normal: one face detected
                this.noFaceStartTime = null;
                this.lastFaceDetectionTime = Date.now();
            }
        } catch (error) {
            console.error('Face detection error:', error);
        }
    }

    /**
     * Check for prohibited objects
     */
    async checkProhibitedObjects() {
        if (!this.videoElement || !this.objectModel) return;

        try {
            const predictions = await this.objectModel.detect(this.videoElement);
            const prohibitedObjects = ['cell phone', 'book', 'laptop', 'remote', 'tv'];

            const detectedProhibited = predictions.filter(pred =>
                prohibitedObjects.includes(pred.class.toLowerCase())
            );

            if (detectedProhibited.length > 0) {
                const objectNames = detectedProhibited.map(p => p.class).join(', ');
                this.logEvent('PROHIBITED_OBJECT',
                    `Detected: ${objectNames}`,
                    'HIGH');
            }
        } catch (error) {
            console.error('Object detection error:', error);
        }
    }

    /**
     * Setup fullscreen detection
     */
    setupFullscreenDetection() {
        document.addEventListener('fullscreenchange', () => {
            if (!document.fullscreenElement) {
                this.logEvent('FULLSCREEN_EXIT',
                    'Student exited fullscreen mode',
                    'MEDIUM');
            }
        });
    }

    /**
     * Setup visibility detection (tab minimized)
     */
    setupVisibilityDetection() {
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.logEvent('TAB_HIDDEN',
                    'Browser tab was hidden or minimized',
                    'MEDIUM');
            }
        });
    }

    /**
     * Setup tab switch detection
     */
    setupTabSwitchDetection() {
        window.addEventListener('blur', () => {
            this.logEvent('WINDOW_BLUR',
                'Student switched to another window or tab',
                'MEDIUM');
        });
    }

    /**
     * Log proctoring event
     */
    logEvent(eventType, description, severity = 'LOW') {
        const event = {
            session_id: this.sessionId,
            event_type: eventType,
            event_description: description,
            severity: severity,
            timestamp: new Date().toISOString()
        };

        this.suspiciousEvents.push(event);
        console.log(`[PROCTOR] ${severity}: ${eventType} - ${description}`);
    }

    /**
     * Flush event log to backend
     */
    async flushEventLog() {
        if (this.suspiciousEvents.length === 0) return;

        const eventsToSend = [...this.suspiciousEvents];
        this.suspiciousEvents = [];

        try {
            for (const event of eventsToSend) {
                await fetch(`${this.apiBase}/student/exam/proctor-log`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(event)
                });
            }
            console.log(`✅ Logged ${eventsToSend.length} proctoring events`);
        } catch (error) {
            console.error('❌ Failed to log events:', error);
            // Re-add events to queue if failed
            this.suspiciousEvents.push(...eventsToSend);
        }
    }

    /**
     * Capture screenshot for evidence
     */
    captureScreenshot() {
        if (!this.videoElement) return null;

        const canvas = document.createElement('canvas');
        canvas.width = this.videoElement.videoWidth;
        canvas.height = this.videoElement.videoHeight;

        const ctx = canvas.getContext('2d');
        ctx.drawImage(this.videoElement, 0, 0);

        return canvas.toDataURL('image/jpeg', 0.7);
    }

    /**
     * Cleanup resources
     */
    cleanup() {
        this.stopMonitoring();

        if (this.cameraStream) {
            this.cameraStream.getTracks().forEach(track => track.stop());
        }

        console.log('✅ Proctoring system cleaned up');
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ExamProctoring;
}
</script>
</body>
</html>