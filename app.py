import streamlit as st
import joblib
import shap
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from predict_ensemble import predict_url
import time
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# Load model
xgb = joblib.load("xgb.pkl")
explainer = shap.TreeExplainer(xgb)

# Page setup
st.set_page_config(page_title="Phishing URL Detector", layout="centered")

# ======== Modern background & style ========
st.markdown("""
    <style>
    body {
        background: linear-gradient(to bottom, white, light-grayish-blue);
    }
    .big-font {
        font-size: 22px !important;
        color: dark-blue;
    }
    .bar-container {
        background-color: light-gray;
        border-radius: 10px;
        width: 100%;
        height: 25px;
        overflow: hidden;
        margin-bottom: 10px;
        border: 1px solid medium-gray;
    }
    .bar {
        height: 100%;
        float: left;
        transition: width 0.3s ease-in-out;
    }
    .title {
        color: dark-blue;
        font-weight: bold;
    }
    .sidebar .sidebar-content {
        background-color: very-light-gray;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Phishing URL Detector with SHAP Explainability")

# Sidebar instructions
st.sidebar.title("🗒️ How to Use")
st.sidebar.markdown("""
1. Enter a URL below  
2. Click **Analyze** or press **Enter**  
3. Check the result & explanation  
4. Download your PDF report  

---

**Tip:** Include `http://` or `https://` for best accuracy.

Built by *Mrinal Basak Shuvo & Team*
""")

# ======== FORM for URL input + Analyze ========
with st.form("url_form"):
    url = st.text_input("🔗 Enter a URL:")
    submitted = st.form_submit_button("Analyze")

# Perform analysis if submitted
if submitted and url:
    start_time = time.time()
    with st.spinner("Analyzing... Please wait"):
        pred, score, features = predict_url(url, return_features=True)
    elapsed_time = round(time.time() - start_time, 2)

    phishing_score = round(score * 100)
    legit_score = 100 - phishing_score

    # Result badge
    st.markdown("### 🔍 Prediction Result")
    result_text = (
        "<b>PHISHING 🚫</b>" if pred == 1 else "<b>LEGITIMATE 🛡️</b>"
    )
    st.markdown(f"**Prediction:** <span class='big-font'>{result_text}</span>", unsafe_allow_html=True)
    st.write(f"**Confidence Score:** {score:.2f}")
    st.write(f"**Time Taken:** {elapsed_time} sec")

    # Confidence bars
    st.markdown("#### 🎯 Confidence Visualization")
    st.markdown("Legitimate")
    st.markdown(f"""
    <div class='bar-container'>
        <div class='bar' style='width:{legit_score}%; background-color:#2ecc71;'></div>
        <div class='bar' style='width:{phishing_score}%; background-color:#ffffff;'></div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("Phishing")
    st.markdown(f"""
    <div class='bar-container'>
        <div class='bar' style='width:{phishing_score}%; background-color:#e74c3c;'></div>
        <div class='bar' style='width:{legit_score}%; background-color:#ffffff;'></div>
    </div>
    """, unsafe_allow_html=True)

    # SHAP Waterfall
    st.markdown("### 📊 SHAP Explanation")
    shap_values = explainer.shap_values(features)
    shap_vals = shap_values[1] if isinstance(shap_values, list) else shap_values

    if isinstance(explainer.expected_value, (list, np.ndarray)):
        base_val = explainer.expected_value[1]
    else:
        base_val = explainer.expected_value

    explanation = shap.Explanation(
        values=shap_vals[0],
        base_values=base_val,
        data=features.iloc[0],
        feature_names=features.columns
    )

    fig = plt.figure(figsize=(10, 6))
    shap.plots.waterfall(explanation, show=False)
    st.pyplot(fig)
    plt.clf()
    plt.close()

    # Save SHAP image for PDF
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_img:
        shap.plots.waterfall(explanation, show=False)
        plt.savefig(tmp_img.name, bbox_inches="tight")
        st.session_state["shap_img_path"] = tmp_img.name
        plt.clf()
        plt.close()

    # Top 5 features
    st.markdown("### 🔎 Top 5 Features")
    shap_impact = pd.Series(shap_vals[0], index=features.columns)
    top5 = shap_impact.abs().sort_values(ascending=False).head(5)
    top5_df = pd.DataFrame({
        "Feature": top5.index,
        "Input Value": features.iloc[0][top5.index].values,
        "SHAP Impact": shap_impact[top5.index].values
    }).reset_index(drop=True)
    st.dataframe(top5_df.style.format({"Input Value": "{:.3f}", "SHAP Impact": "{:.3f}"}))

    # Save for PDF
    st.session_state["report_data"] = {
        "url": url,
        "prediction": "Phishing" if pred == 1 else "Legitimate",
        "score": score,
        "elapsed_time": elapsed_time,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    st.session_state["top5"] = top5_df
    st.session_state["analysis_done"] = True

# PDF generation
if st.session_state.get("analysis_done"):
    if st.button("📄 Save PDF Report"):
        report = st.session_state["report_data"]
        top5 = st.session_state["top5"]
        shap_img_path = st.session_state["shap_img_path"]

        if os.path.exists(shap_img_path):
            pdf = FPDF()
            pdf.add_page()

            pdf.set_font("Arial", 'B', 16)
            pdf.set_text_color(33, 41, 122)
            pdf.cell(200, 10, txt="Phishing URL Detection Report", ln=True, align="C")
            pdf.ln(10)

            # URL with color
            pdf.set_font("Arial", 'B', 12)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(200, 10, txt="URL Analyzed:", ln=True)
            pdf.set_font("Arial", 'B', 12)
            if report['prediction'] == "Legitimate":
                pdf.set_text_color(0, 150, 0)
            else:
                pdf.set_text_color(200, 0, 0)
            pdf.multi_cell(0, 10, report['url'])
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)

            # Details
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt="Prediction Summary:", ln=True)
            pdf.set_font("Arial", '', 12)
            pdf.multi_cell(0, 10,
                f"Prediction: {report['prediction']}\n"
                f"Confidence Score: {report['score']*100:.2f}%\n"
                f"Time Taken: {report['elapsed_time']} seconds\n"
                f"Timestamp: {report['timestamp']}"
            )
            pdf.ln(5)

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt="Confidence Scores:", ln=True)
            pdf.set_font("Arial", '', 12)
            pdf.multi_cell(0, 10,
                f"Legitimate: {100 - report['score']*100:.2f}%\n"
                f"Phishing: {report['score']*100:.2f}%"
            )
            pdf.ln(10)

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt="SHAP Explanation:", ln=True)
            pdf.set_font("Arial", '', 12)
            pdf.multi_cell(0, 10, "Feature impact waterfall plot:")
            pdf.image(shap_img_path, x=10, w=180)
            pdf.ln(10)

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt="Top 5 Contributing Features:", ln=True)
            pdf.set_font("Arial", '', 12)

            pdf.set_fill_color(230, 230, 250)
            pdf.cell(60, 10, "Feature", border=1, fill=True, align='C')
            pdf.cell(60, 10, "Input Value", border=1, fill=True, align='C')
            pdf.cell(60, 10, "SHAP Impact", border=1, fill=True, align='C')
            pdf.ln(10)

            for _, row in top5.iterrows():
                pdf.cell(60, 10, row['Feature'], border=1, align='C')
                pdf.cell(60, 10, f"{row['Input Value']:.3f}", border=1, align='C')
                pdf.cell(60, 10, f"{row['SHAP Impact']:.3f}", border=1, align='C')
                pdf.ln(10)

            pdf.set_font("Arial", 'I', 10)
            pdf.cell(200, 10, txt="Built by Mrinal Basak Shuvo", ln=True, align="C")
            pdf.set_font("Arial", 'I', 10)
            pdf.set_text_color(0, 0, 255)
            pdf.cell(200, 10, txt="View the full project on GitHub", ln=True, align="C", link="https://github.com/mbs57/Phishing")

            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
                pdf.output(tmp_pdf.name)
                st.success("✅ Report ready!")

            with open(tmp_pdf.name, "rb") as file:
                pdf_bytes = file.read()

            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name="Phishing_Report.pdf",
                mime="application/pdf"
            )

# Home button
if st.button("🏠 Back to Home"):
    st.session_state.clear()
    st.rerun()

# Footer
st.markdown("""
---
<center> <sub>Model: Ensemble - DWGF (Dynamic Weighted Gradient Fusion) Created with (RFC, XGBC, LGBM)<br> Built by Mrinal Basak Shuvo & Team</sub> </center>
""", unsafe_allow_html=True)
