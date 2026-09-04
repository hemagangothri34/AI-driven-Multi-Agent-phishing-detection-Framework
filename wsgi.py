import os
import sys

# Compute paths to nested phishing_detection_framework directory
base_dir = os.path.dirname(os.path.abspath(__file__))
framework_dir = os.path.join(base_dir, 'Final Year project', 'phishing_detection_framework')
webapp_dir = os.path.join(framework_dir, 'webapp')

for d in [framework_dir, webapp_dir]:
    if d not in sys.path and os.path.exists(d):
        sys.path.insert(0, d)

from webapp.app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
