class URLAnalysisAgent:
    """
    Agent responsible for analyzing URLs using the feature and ML agents.
    """
    def __init__(self, feature_agent, ml_agent):
        self.feature_agent = feature_agent
        self.ml_agent = ml_agent
        
    def analyze(self, url):
        """
        Extracts features and predicts if the URL is phishing.
        """
        # 1. Extract features using the FeatureExtractionAgent
        features = self.feature_agent.extract_url_features(url)
        
        # 2. Get prediction using the MachineLearningAgent
        prediction, confidence = self.ml_agent.predict_url(features)
        
        return {
            "type": "URL",
            "input": url,
            "prediction": "Phishing" if prediction == 1 else "Safe",
            "confidence": confidence if prediction == 1 else 1.0 - confidence
        }
