cd C:\network-intrusion-detection-system\frontend
npm start

cd C:\network-intrusion-detection-system
.\.venv\Scripts\Activate.ps1
uvicorn backend.app:app --reload

cd C:\network-intrusion-detection-system
.\.venv\Scripts\Activate.ps1
python -m backend.realtime.packet_capture

ping -4 google.com