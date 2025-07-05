import joblib
import shap
import numpy as np
import streamlit as st
from predict_ensemble import predict_url

# Load base LightGBM model and SHAP explainer once at startup
lgbm = joblib.load("best_lgbm.pkl")  # base LightGBM model (not calibrated)
explainer = shap.TreeExplainer(lgbm)

def main():
    st.title("Phishing URL Detector with SHAP Explainability")

    url = st.text_input("Enter URL to check:")

    if url:
        with st.spinner("Analyzing..."):
            pred, score, features = predict_url(url, return_features=True)
            
            st.markdown(f"### 🔍 URL Score: {score:.2f}")
            st.markdown(f"### Result: {'🛑 Phishing' if pred == 1 else '✅ Legitimate'}")

            # Calculate SHAP values
            shap_values = explainer.shap_values(features)

            # Show top 10 SHAP feature contributions (absolute value)
            shap_vals_abs = np.abs(shap_values[1][0])
            top_indices = np.argsort(-shap_vals_abs)[:10]

            st.markdown("### Top SHAP feature contributions:")
            for idx in top_indices:
                fname = features.columns[idx]
                fvalue = shap_values[1][0][idx]
                st.write(f"{fname}: {fvalue:.4f}")

            # Plot SHAP summary plot
            st.markdown("### SHAP Summary Plot:")
            # shap.summary_plot normally uses matplotlib.pyplot.show() internally
            # Use st.pyplot to show the plot inside Streamlit
            import matplotlib.pyplot as plt
            plt.figure(figsize=(10, 6))
            shap.summary_plot(shap_values[1], features, show=False)
            st.pyplot(plt.gcf())
            plt.clf()

if __name__ == "__main__":
    main()