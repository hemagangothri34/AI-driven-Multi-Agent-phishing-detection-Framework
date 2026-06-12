import os
import sys

# Import custom agents
from agents.feature_agent import FeatureExtractionAgent
from agents.ml_agent import MachineLearningAgent
from agents.decision_agent import DecisionAgent

def main():
    print("==========================================================")
    print(" AI-Driven Multi-Agent Phishing & Smishing Framework ")
    print("==========================================================\n")
    
    # Model paths
    model_dir = os.path.join('model', 'saved_models')
    url_model_path = os.path.join(model_dir, 'url_model.pkl')
    sms_model_path = os.path.join(model_dir, 'sms_model.pkl')
    tfidf_path = os.path.join(model_dir, 'tfidf_vectorizer.pkl')
    
    if not (os.path.exists(url_model_path) and os.path.exists(sms_model_path)):
        print("Error: Models not found! Please run the training script first.")
        print("Run command: python model/train_model.py")
        sys.exit(1)
        
    print("[*] Initializing Framework Agents...")
    
    # Initialize Core Agents
    feature_agent = FeatureExtractionAgent(tfidf_path=tfidf_path)
    ml_agent = MachineLearningAgent(url_model_path=url_model_path, sms_model_path=sms_model_path)
    
    # Initialize Coordination Agent
    decision_agent = DecisionAgent(feature_agent=feature_agent, ml_agent=ml_agent)
    
    print("[*] Agents loaded successfully.\n")
    print("--- Running Test Examples ---\n")
    
    # Sample Test Cases defined in the prompt requirements
    test_url = "http://secure-login-bank123.com"
    test_sms = "Verify your bank account immediately by clicking this link"
    
    # Test URL Analysis
    print("-> Test Case 1: URL Verification")
    url_result = decision_agent.analyze_input(test_url, input_type="URL")
    print(f"Input URL: {url_result['Input Text']}")
    print(f"Output:")
    print(f"  {url_result['Verdict']}")
    print(f"  Confidence Score: {url_result['Confidence Score']}")
    print("-" * 50)
    
    # Test SMS Analysis
    print("-> Test Case 2: SMS Verification")
    sms_result = decision_agent.analyze_input(test_sms, input_type="SMS")
    print(f"Input SMS: '{sms_result['Input Text']}'")
    print(f"Output:")
    print(f"  {sms_result['Verdict']}")
    print(f"  Confidence Score: {sms_result['Confidence Score']}")
    print("==========================================================\n")

if __name__ == "__main__":
    # Ensure this is executed from root dir
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)
        
    main()
