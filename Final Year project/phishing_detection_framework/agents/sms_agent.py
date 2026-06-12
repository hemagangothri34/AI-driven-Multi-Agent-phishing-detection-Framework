class SMSAnalysisAgent:
    """
    Agent responsible for analyzing SMS messages using the feature and ML agents.
    """
    def __init__(self, feature_agent, ml_agent):
        self.feature_agent = feature_agent
        self.ml_agent = ml_agent
        
    def analyze(self, sms_text):
        """
        Extracts features and predicts if the SMS is smishing.
        """
        # 1. Extract features using the FeatureExtractionAgent
        features = self.feature_agent.extract_sms_features(sms_text)
        
        # 2. Get prediction using the MachineLearningAgent
        prediction, confidence = self.ml_agent.predict_sms(features)
        
        return {
            "type": "SMS",
            "input": sms_text,
            "prediction": "Smishing" if prediction == 1 else "Safe",
            "confidence": confidence if prediction == 1 else 1.0 - confidence
        }
