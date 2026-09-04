import os
import sys

base_dir = os.path.dirname(os.path.abspath(__file__))
webapp_dir = os.path.join(base_dir, 'webapp')

for d in [base_dir, webapp_dir]:
    if d not in sys.path and os.path.exists(d):
        sys.path.insert(0, d)

from webapp.app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
