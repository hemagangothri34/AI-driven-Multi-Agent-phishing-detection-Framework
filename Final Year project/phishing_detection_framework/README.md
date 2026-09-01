# AI-Driven Multi-Agent Phishing URL & Smishing Detection Framework

This robust project is a complete working implementation of a multi-agent framework designed to detect phishing URLs and smishing (SMS phishing) messages. It secures FinTech communication using machine learning techniques.

**Academic Submission Note:** Suitable for submission as a Final Year B.Tech project in Artificial Intelligence & Data Science at Parul University, under the guidance of Prof. Nikunj Bhavsar.

## Architecture & Agents
The system follows a Multi-Agent logic:
- `FeatureExtractionAgent`: Extracts textual and length-based features for URLs and computes TF-IDF representations for SMS messages.
- `MachineLearningAgent`: Handles evaluating Machine Learning models (Random Forest for URLs, Logistic Regression for SMS) to generate predictions.
- `URLAnalysisAgent`: Prepares data strictly for URL analysis.
- `SMSAnalysisAgent`: Prepares data strictly for SMS analysis.
- `DecisionAgent`: Combines individual agent outputs to arrive at a final security verdict with a measurable confidence score.

## Installation & Setup
1. **Requires Python 3.8+**
2. **Install necessary dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### 1. Train the Machine Learning Models
You must train the agent's ML classifiers before it can evaluate outputs.
```bash
python model/train_model.py
```
This generates trained weights and TF-IDF data internally into `model/saved_models/`. It will print evaluation stats and accuracy based on the provided dataset logic.

### 2. Run the Command Line Interface (CLI)
You can directly test the framework via the terminal orchestrator using the provided examples:
```bash
python main.py
```

### 3. Start the Web Interface
For an interactive demonstration with a graphical front-end UI:
```bash
python webapp/app.py
```
Navigate to `http://127.0.0.1:5000` locally in your web browser. Follow on-screen fields to provide URL/SMS data and let the agent framework calculate the security integrity.

deployed https://ai-driven-multi-agent-phishing-detection-p3ek.onrender.com
