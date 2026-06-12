import pickle
import os

class MachineLearningAgent:
    """
    Agent responsible for serving machine learning models for predictions.
    """
    def __init__(self, url_model_path, sms_model_path):
        self.url_model = None
        self.sms_model = None
        
        if os.path.exists(url_model_path):
            with open(url_model_path, 'rb') as f:
                self.url_model = pickle.load(f)
        else:
            print(f"Warning: URL model not found at {url_model_path}")
                
        if os.path.exists(sms_model_path):
            with open(sms_model_path, 'rb') as f:
                self.sms_model = pickle.load(f)
        else:
            print(f"Warning: SMS model not found at {sms_model_path}")

    def predict_url(self, features):
        """
        Predict if a URL is phishing based on given features.
        Returns: (prediction_label, confidence_score)
        """
        if self.url_model is None:
            raise ValueError("URL model not loaded!")
            
        prob = self.url_model.predict_proba(features)[0][1]
        pred = self.url_model.predict(features)[0]
        return int(pred), float(prob)

    def predict_sms(self, features):
        """
        Predict if an SMS is smishing based on given features.
        Returns: (prediction_label, confidence_score)
        """
        if self.sms_model is None:
            raise ValueError("SMS model not loaded!")
            
        # For Logistic Regression or RF
        prob = self.sms_model.predict_proba(features)[0][1]
        pred = self.sms_model.predict(features)[0]
        return int(pred), float(prob)
