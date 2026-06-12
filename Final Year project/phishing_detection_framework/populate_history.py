import json
import random
import csv
import os
from datetime import datetime, timedelta

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_DATA_PATH = os.path.join(BASE_DIR, 'dataset', 'phishing_urls.csv')
SMS_DATA_PATH = os.path.join(BASE_DIR, 'dataset', 'smishing_sms.csv')
HISTORY_FILE = os.path.join(BASE_DIR, 'webapp', 'history.json')

# Helper to read CSV safely
def read_csv_samples(path, max_samples=30):
    samples = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_samples:
                    break
                # Phishing URLs CSV uses 'url' and 'label'
                if 'url' in row:
                    samples.append((row['url'], int(row['label'])))
                # Smishing SMS CSV uses 'message' and 'label'
                elif 'message' in row:
                    samples.append((row['message'], int(row['label'])))
    except Exception as e:
        print(f"Error reading {path}: {e}")
    return samples

def generate_mock_log(input_type, input_text, label, timestamp):
    """
    Generate highly realistic mock metadata for a log entry.
    Label: 1 means malicious, 0 means safe.
    """
    
    # Verdicts and Confidence
    if label == 1:
        # Determine if it's high confidence (Critical) or medium confidence (Suspicious)
        is_critical = random.choice([True, True, True, False]) # 75% chance critical
        verdict = f"Critical {'Phishing' if input_type == 'URL' else 'Smishing'} Attack Detected" if is_critical else f"Suspicious {input_type} (Under threshold)"
        risk_level = "High" if is_critical else "Medium"
        confidence = f"{round(random.uniform(95.0, 99.9) if is_critical else random.uniform(80.0, 94.9), 2)}%"
    else:
        verdict = f"Safe {input_type} Content"
        risk_level = "Low"
        confidence = f"{round(random.uniform(85.0, 99.9), 2)}%"
        
    # Technical Metadata
    protocols = ['TCP', 'UDP', 'QUIC', 'TLS 1.3']
    models_used = ['Ensemble-XGB', 'DistilBERT-v2', 'Heuristic-Engine', 'Lexical-Analyzer']
    node_regions = ['us-east-1', 'eu-west-2', 'ap-southeast-1', 'ca-central-1']
    
    metadata = {
        "ingest_node_ip": f"{random.randint(10, 192)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "detection_latency_ms": f"{round(random.uniform(12.5, 450.2), 1)}ms",
        "routing_protocol": random.choice(protocols),
        "primary_model": random.sample(models_used, random.randint(1, 3)),
        "node_region": random.choice(node_regions),
        "heuristic_weights": {
            "lexical": round(random.uniform(0.1, 0.9), 2),
            "network": round(random.uniform(0.1, 0.9), 2),
            "nlp": round(random.uniform(0.1, 0.9), 2)
        }
    }
    
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "input_type": input_type,
        "input_text": input_text[:120] + "..." if len(input_text) > 120 else input_text,
        "verdict": verdict,
        "risk_level": risk_level,
        "confidence": confidence,
        "advanced_metadata": metadata
    }

def main():
    print("Reading simulation datasets...")
    url_samples = read_csv_samples(URL_DATA_PATH, max_samples=40)
    sms_samples = read_csv_samples(SMS_DATA_PATH, max_samples=40)
    
    if not url_samples and not sms_samples:
        print("Warning: Could not read datasets to generate samples.")
        return

    print("Generating simulated telemetry...")
    history = []
    
    # Set starting time to 3 days ago
    current_time = datetime.now() - timedelta(days=3)
    end_time = datetime.now()
    
    pool = [(samp[0], samp[1], "URL") for samp in url_samples] + \
           [(samp[0], samp[1], "SMS") for samp in sms_samples]
           
    # Generate 80 entries over the 3 days
    entry_count = 80
    time_increment = (end_time - current_time) / entry_count
    
    # Let's shuffle the pool so they aren't all URLs then all SMS
    random.shuffle(pool)
    
    for i in range(entry_count):
        # Pick a random sample from pool
        text, label, type_ = random.choice(pool)
        
        # Add some random jitter to the timestamp
        jitter = timedelta(minutes=random.randint(1, 60))
        entry_time = current_time + (time_increment * i) + jitter
        
        # Cap entry_time at datetime.now()
        if entry_time > datetime.now():
            entry_time = datetime.now()
            
        history.append(generate_mock_log(type_, text, label, entry_time))

    print(f"Writing {len(history)} entries to {HISTORY_FILE}...")
    
    # Read existing history if there is any, but since we are overriding let's just clear
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=4)
        
    print("Done! Restart or refresh your application to view the dense data sets.")

if __name__ == "__main__":
    main()
