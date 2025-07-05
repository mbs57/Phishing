import joblib
import numpy as np
import pandas as pd
from feature_extractor import extract_features

# Load models and scaler
scaler = joblib.load("scaler.pkl")
rf = joblib.load("rf_calibrated.pkl")
xgb = joblib.load("xgb_calibrated.pkl")
lgbm = joblib.load("lgbm_calibrated.pkl")
ensemble_weights = joblib.load("ensemble_weights.pkl")
ensemble_threshold = joblib.load("ensemble_threshold.pkl")

# ✅ Correct feature names
feature_names = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report"
]

def predict_url(url, return_features=False):
    # Extract features and assign column names
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=feature_names)
    
    # Scale the DataFrame but keep feature names
    features_scaled = scaler.transform(features_df)
    features_scaled_df = pd.DataFrame(features_scaled, columns=feature_names)

    # Predict using each model
    rf_prob = rf.predict_proba(features_scaled_df)[0][1]
    xgb_prob = xgb.predict_proba(features_scaled_df)[0][1]
    lgbm_prob = lgbm.predict_proba(features_scaled_df)[0][1]

    # Weighted ensemble
    model_probs = np.array([rf_prob, xgb_prob, lgbm_prob])
    final_score = np.dot(model_probs, ensemble_weights)

    prediction = 1 if final_score >= ensemble_threshold else 0

    # ✅ Return DataFrame with column names for SHAP, not raw array
    if return_features:
        return prediction, final_score, features_scaled_df
    else:
        return prediction, final_score
