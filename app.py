"""
Phishing URL Detection Web Application
Backend: Flask + Machine Learning
Uses RandomForestClassifier trained on UCI Phishing Websites Dataset

Dataset Information:
- Source: UCI Machine Learning Repository
- URL: https://archive.ics.uci.edu/ml/datasets/Phishing+Websites
- Instances: 11,055 real phishing and legitimate websites
- Features: 30 URL-based and website characteristics
- Accuracy: ~95% on test set

Model Training:
- Run: python train_model.py (to train on real UCI dataset)
- Model is saved as: model.pkl
- Uses: RandomForestClassifier with 100 estimators
- Training Data: Real phishing and legitimate websites from UCI ML Repository

To train the model on real data:
    cd phishing-detector
    python train_model.py
"""


from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import pickle
import os
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from utils import (extract_features, is_valid_url, extract_domain_info, 
                   get_brand_info, get_hosting_provider, get_location_from_ip,
                   get_certificate_info, scan_threats, generate_explanation,
                   rule_based_check, compute_hybrid_score, apply_override_rules)
import warnings

warnings.filterwarnings('ignore')

app = Flask(__name__)

# Enable CORS for all routes
CORS(app, resources={r"/*": {"origins": "*"}})

# Path for model
MODEL_PATH = 'model.pkl'
SCALER_PATH = 'scaler.pkl'


def train_model():
    """
    Train a RandomForestClassifier on UCI Phishing Websites Dataset
    
    IMPORTANT: Before running this, first execute:
        python train_model.py
    
    This function is a fallback that trains on a small sample dataset.
    For production, use the real UCI dataset via train_model.py script.
    
    Dataset Info:
    - Source: UCI Machine Learning Repository
    - URL: https://archive.ics.uci.edu/ml/datasets/Phishing+Websites
    - 11,055 real website samples with 30 URL-based features
    - Trained model accuracy: ~95%
    
    Real Dataset Features (30 total):
    - IP address detection
    - URL length analysis
    - HTTPS/SSL certificate status
    - Domain characteristics
    - Server-side features
    - Client-side features
    - And 24 more URL-based indicators
    
    To use the real dataset:
        1. Run: python train_model.py
        2. This downloads and processes UCI dataset
        3. Trains model with full 11,055 samples
        4. Saves as model.pkl
    """
    print("\n" + "="*60)
    print("⚠️  NOTICE: Using fallback synthetic dataset")
    print("="*60)
    print("🔗 For better model accuracy, use real UCI dataset:")
    print("   Command: python train_model.py")
    print("="*60)
    print("\n📚 Training model on sample dataset...")
    
    # Sample training data with 30 features (UCI dataset format)
    # Features match the UCI Phishing Dataset structure
    
    # Safe URLs features (label = 0) - 30 features each
    safe_urls_features = [
        # Legitimate website patterns
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # google.com
        [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # mail.google.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # github.com
        [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # docs.python.org
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # amazon.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # facebook.com
        [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # api.github.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # wikipedia.org
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # stackoverflow.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # twitter.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # reddit.com
        [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # drive.google.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # linkedin.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # youtube.com
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1],  # instagram.com
    ]
    
    # Phishing URLs features (label = 1) - 30 features each
    phishing_urls_features = [
        # Phishing website patterns
        [-1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Fake google
        [-1, 0, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # IP-based phishing
        [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Dash domain phishing
        [-1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Complex phishing
        [-1, 0, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Account phishing
        [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Verify account
        [-1, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Update profile
        [-1, 0, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Confirm phishing
        [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Login phishing
        [-1, 0, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # IP path phishing
        [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Domain phishing
        [-1, 0, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Suspicious URL
        [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Multi-level phishing
        [-1, 0, -1, -1, 0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Fake account
        [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 1],  # Verification scam
    ]
    
    # Combine features and labels
    X_train = np.array(safe_urls_features + phishing_urls_features)
    y_train = np.array([0] * len(safe_urls_features) + [1] * len(phishing_urls_features))
    
    # Train RandomForestClassifier with optimized parameters
    model = RandomForestClassifier(
        n_estimators=100,           # 100 decision trees
        max_depth=10,               # Max tree depth to prevent overfitting
        min_samples_split=5,        # Min samples to split a node
        min_samples_leaf=2,         # Min samples required at leaf node
        random_state=42,            # For reproducibility
        n_jobs=-1                   # Use all CPU cores
    )
    
    model.fit(X_train, y_train)
    
    # Save model to disk for persistence
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    print("✅ Fallback model trained and saved!")
    print("\n📌 RECOMMENDATION: Run 'python train_model.py' for better accuracy\n")
    return model


def load_model():
    """
    Load trained model from disk
    If model doesn't exist, train and save it
    
    Returns:
        RandomForestClassifier: Trained model
    """
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        print("Model loaded successfully!")
        return model
    else:
        print("Model not found. Training new model...")
        return train_model()


# Load model when app starts
model = load_model()


@app.route('/')
def home():
    """
    Home page - Project information and features
    """
    return render_template('home.html')


@app.route('/checker')
def checker():
    """
    URL Checker page - URL analysis tool
    """
    return render_template('checker.html')


@app.route('/predict', methods=['POST'])
def predict():
    """
    Hybrid Prediction Endpoint
    Combines ML model (70% weight) + Rule-based scoring (30% weight)
    Applies override rules for obvious phishing/safe cases
    """
    try:
        # Get URL from request
        data = request.get_json()
        url = data.get('url', '').strip()
        
        # Validate URL
        if not url:
            return jsonify({
                'success': False,
                'prediction': 'Invalid URL',
                'confidence': 0,
                'error': 'Please enter a URL to scan.'
            }), 400
        
        # Auto-add protocol if missing
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        # Reject garbage like "httpfree", "abcxyz" etc.
        if not is_valid_url(url):
            return jsonify({
                'success': False,
                'prediction': 'Invalid URL',
                'confidence': 0,
                'error': 'Invalid URL format. Please enter a valid URL like https://example.com'
            }), 400
        
        # ===== STEP 1: Extract features for ML model =====
        features_dict, features_list = extract_features(url)
        
        # ===== STEP 2: ML Prediction (70% weight) =====
        features_array = np.array([features_list])
        prediction_raw = model.predict(features_array)[0]
        confidence_scores = model.predict_proba(features_array)[0]
        
        # ML phishing probability (0-100)
        ml_phishing_score = confidence_scores[1] * 100  # probability of class 1 (phishing)
        
        # ===== STEP 3: Rule-based scoring (30% weight) =====
        rule_result = rule_based_check(url, features_dict)
        rule_risk_score = rule_result['risk_score']
        
        # ===== STEP 4: Hybrid score = (ML * 0.7) + (Rules * 0.3) =====
        hybrid = compute_hybrid_score(ml_phishing_score, rule_risk_score)
        
        # ===== STEP 5: Apply override rules for obvious cases =====
        final = apply_override_rules(url, rule_result, hybrid)
        
        # Final label: Safe / Suspicious / Phishing
        result = final['label']
        final_score = final['final_score']
        
        # ===== STEP 6: Extract domain & advanced info =====
        domain_info = extract_domain_info(url)
        brand_info = get_brand_info(domain_info['domain'])
        hosting_info = get_hosting_provider(domain_info['ip_address'])
        location_info = get_location_from_ip(domain_info['ip_address'])
        cert_info = get_certificate_info(domain_info['domain'])
        threat_info = scan_threats(domain_info['domain'])
        
        # ===== STEP 7: Generate explanations (ML + Rules combined) =====
        explanations = generate_explanation(
            features_dict, url, result, final_score,
            rule_reasons=rule_result['reasons']
        )
        
        # ===== STEP 8: Build comprehensive response =====
        response_data = {
            'success': True,
            'url': url,
            
            # Main prediction result
            'prediction': result,          # "Safe" / "Suspicious" / "Phishing"
            'confidence': round(final_score, 2),  # Hybrid score 0-100
            
            # Score breakdown for transparency
            'score_breakdown': {
                'ml_phishing_probability': round(ml_phishing_score, 2),
                'rule_risk_score': rule_risk_score,
                'ml_contribution': final['ml_contribution'],
                'rule_contribution': final['rule_contribution'],
                'final_score': final_score,
                'override_applied': final.get('override_applied')
            },
            
            # Extracted ML features
            'features': features_dict,
            
            # Rule-based reasons (for frontend display)
            'rule_reasons': rule_result['reasons'],
            
            # Human-readable message
            'message': f'URL is {result} (Risk Score: {final_score:.1f}%)',
            
            # Scan metadata
            'scan_results': {
                'source_url': url,
                'detection_date': datetime.now().strftime('%B %d %Y, %I:%M:%S %p'),
                'job_id': f"JOB-{np.random.randint(100000, 999999)}",
                'method': 'Hybrid (ML 70% + Rules 30%)'
            },
            
            # Domain Information
            'domain_info': domain_info,
            'brand': brand_info['name'],
            'brand_detected': brand_info['detected'],
            
            # Hosting Information
            'hosting': {
                'provider': hosting_info['name'],
                'type': hosting_info['type'],
                'asn': 'N/A'
            },
            
            # Location Information
            'location': location_info,
            
            # Certificate Information
            'certificate': cert_info,
            
            # Threat Intelligence
            'threat_intelligence': threat_info,
            
            # Explainable AI
            'explanation': explanations
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Error in prediction: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'Error processing request: {str(e)}',
            'prediction': None,
            'confidence': None
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    Returns status of the application
    """
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None
    }), 200


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔒 Phishing URL Detection Application Started")
    print("="*60)
    print("Server running on: http://localhost:5000")
    print("="*60 + "\n")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
