import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import re

from feature_extractor import extract_features

# Load models and scaler
scaler = joblib.load("scaler.pkl")
rf = joblib.load("rf.pkl")
xgb = joblib.load("xgb.pkl")
lgbm = joblib.load("lgbm.pkl")
ensemble_weights = joblib.load("ensemble_weights.pkl")
ensemble_threshold = joblib.load("ensemble_threshold.pkl")

# ✅ Correct feature names (must match extractor order)
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
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "popUpWidnow",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report"
]

# ✅ Helper: Check if hostname is an IP or hex IP
def uses_ip(url):
    hostname = urlparse(url).hostname or ""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hex_pattern = r'^0x[a-fA-F0-9]+$'
    if re.match(ip_pattern, hostname) or re.match(hex_pattern, hostname):
        return True
    return False

# ✅ Main prediction function
def predict_url(url, return_features=False):
    # Extract features
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=feature_names)

    # Scale features
    features_scaled = scaler.transform(features_df)
    features_scaled_df = pd.DataFrame(features_scaled, columns=feature_names)

    # Predict individual models
    rf_prob = rf.predict_proba(features_scaled_df)[0][1]
    xgb_prob = xgb.predict_proba(features_scaled_df)[0][1]
    lgbm_prob = lgbm.predict_proba(features_scaled_df)[0][1]

    # Weighted ensemble
    model_probs = np.array([rf_prob, xgb_prob, lgbm_prob])
    final_score = np.dot(model_probs, ensemble_weights)

    # ✅ Post-boost: IP or brand-like domain → slight penalty boost
    if uses_ip(url):
        final_score = min(final_score + 0.4, 1.0)

    # Final decision
    prediction = 1 if final_score >= ensemble_threshold else 0

    if return_features:
        return prediction, final_score, features_scaled_df
    else:
        return prediction, final_score
