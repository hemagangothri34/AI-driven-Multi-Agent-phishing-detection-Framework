import re
import pickle
import os
import numpy as np

class FeatureExtractionAgent:
    """
    Agent responsible for extracting features from inputs (URLs and SMS).
    """
    def __init__(self, tfidf_path=None):
        self.tfidf_path = tfidf_path
        self.tfidf_vectorizer = None
        
        if self.tfidf_path and os.path.exists(self.tfidf_path):
            with open(self.tfidf_path, 'rb') as f:
                self.tfidf_vectorizer = pickle.load(f)

    def extract_url_features(self, url):
        """
        Extract numeric features from URL for the Random Forest model.
        Features: [length, num_dots, domain_age, has_https, num_special_chars, has_ip, num_hyphens, has_at_symbol]
        """
        length = len(url)
        num_dots = url.count('.')
        
        # Mock domain age (older domains are generally safer, standard ~365 days, but random for now)
        # We will use simple heuristics: common known domains have high age.
        domain_age = 3650 if any(d in url for d in ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'linkedin.com', 'apple.com', 'microsoft.com', 'chatgpt.com', 'openai.com']) else np.random.randint(10, 365)
        
        has_https = 1 if url.startswith("https") else 0
        special_chars = sum(url.count(c) for c in ['?', '=', '_', '~', '%', '&'])
        
        # IP address usage (basic regex match)
        has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        
        num_hyphens = url.count('-')
        
        has_at_symbol = 1 if '@' in url else 0
        
        return np.array([[length, num_dots, domain_age, has_https, special_chars, has_ip, num_hyphens, has_at_symbol]])

    def extract_sms_features(self, text):
        """
        Extract TF-IDF features for SMS text.
        """
        if self.tfidf_vectorizer is None:
            raise ValueError("TF-IDF vectorizer is not loaded. Cannot extract text features.")
            
        return self.tfidf_vectorizer.transform([text])
