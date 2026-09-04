import pandas as pd
import numpy as np
import pickle
import sys
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Ensure agents module can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agents.feature_agent import FeatureExtractionAgent

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def train_url_model():
    print("--- Training URL Phishing Detection Model ---")
    data_path = os.path.join(BASE_DIR, 'dataset', 'phishing_urls.csv')
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        return
        
    df = pd.read_csv(data_path)
    
    agent = FeatureExtractionAgent()
    features = []
    for url in df['url']:
        f = agent.extract_url_features(url)
        features.append(f[0])
        
    X = np.array(features)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    print(f"URL Model Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    
    model_dir = os.path.join(BASE_DIR, 'model', 'saved_models')
    os.makedirs(model_dir, exist_ok=True)
    
    url_save_path = os.path.join(model_dir, 'url_model.pkl')
    with open(url_save_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"URL model saved to {url_save_path}\n")

def train_sms_model():
    print("--- Training Smishing Detection Model ---")
    data_path = os.path.join(BASE_DIR, 'dataset', 'smishing_sms.csv')
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        return
        
    df = pd.read_csv(data_path)
    
    vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
    X = vectorizer.fit_transform(df['message'])
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = LogisticRegression(random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    print(f"SMS Model Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    
    model_dir = os.path.join(BASE_DIR, 'model', 'saved_models')
    os.makedirs(model_dir, exist_ok=True)
    
    sms_save_path = os.path.join(model_dir, 'sms_model.pkl')
    vectorizer_save_path = os.path.join(model_dir, 'tfidf_vectorizer.pkl')
    with open(sms_save_path, 'wb') as f:
        pickle.dump(model, f)
    with open(vectorizer_save_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    print(f"SMS model and TF-IDF vectorizer saved to {model_dir}\n")

if __name__ == "__main__":
    os.chdir(BASE_DIR)
    train_url_model()
    train_sms_model()
