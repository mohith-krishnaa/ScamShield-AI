from datetime import datetime, timezone
import json
from pathlib import Path
import joblib
import streamlit as st
from analyzer import analyze_indicators, analyze_text_indicators, risk_level, risk_score, url_findings

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / 'models' / 'scamshield_model.joblib'
st.set_page_config(page_title='ScamShield AI', page_icon='🛡️', layout='wide')
st.title('🛡️ ScamShield AI')
st.subheader('Pause. Inspect. Verify.')
st.write('Educational local-first analyzer for suspicious messages and URLs. Results are warning signals, not proof of fraud or safety.')

@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None

model = load_model()
if model is None:
    st.warning('The trained model is missing. Run python train_model.py from the project directory, then refresh.')
    st.stop()

with st.sidebar:
    st.header('About this prototype')
    st.write('NLP: TF-IDF + Logistic Regression')
    st.write('Explainability: transparent text and URL heuristics')
    st.write('Processing: local inference; no external AI API')
    st.caption('Do not paste real OTPs, passwords, recovery codes, card details, or sensitive private information.')

samples = {'Choose an example': '', 'Suspicious bank message': 'URGENT: Your bank account will be blocked today. Verify your account and share the OTP at http://secure-bank-verify.example', 'Routine reminder': 'Reminder: Your appointment is scheduled for 3 PM tomorrow. Please arrive 10 minutes early.', 'Prize bait': 'Congratulations! You won a free gift. Click the link and pay a small processing fee to claim your reward.', 'Suspicious URL': 'http://secure-account-login-verify.example/path'}
choice = st.selectbox('Load a demo example (optional)', list(samples))
message = st.text_area('Message or URL to analyze', value=samples[choice], height=180, max_chars=10000, placeholder='Paste suspicious message text or a URL here…')
if st.button('Analyze content', type='primary', use_container_width=True):
    if not message.strip():
        st.error('Enter a message or URL first.')
    else:
        probs = model.predict_proba([message])[0]
        classes = list(model.classes_)
        scam_prob = float(probs[classes.index('scam')]) if 'scam' in classes else 0.5
        label = str(model.predict([message])[0])
        flags, urls = analyze_indicators(message)
        text_flags = analyze_text_indicators(message)
        url_count = sum(bool(url_findings(url)) for url in urls)
        score = risk_score(scam_prob * 100, len(text_flags), url_count)
        level, icon = risk_level(score)
        st.session_state['last_result'] = {'timestamp_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'predicted_label': label, 'risk_score': score, 'risk_level': level, 'model_scam_score_percent': round(scam_prob * 100, 2), 'warning_signs': flags, 'urls_found': urls, 'url_inspection': [{'url': url, 'findings': url_findings(url)} for url in urls], 'input': message, 'note': 'Demonstration score only; not a calibrated probability or guarantee.'}

if 'last_result' in st.session_state:
    r = st.session_state['last_result']
    st.divider()
    st.subheader(r['risk_level'] + ' ' + risk_level(r['risk_score'])[1])
    c1, c2, c3 = st.columns(3)
    c1.metric('Demo risk index', f"{r['risk_score']}/100")
    c2.metric('Model label', r['predicted_label'].title())
    c3.metric('Warning indicators', len(r['warning_signs']))
    st.progress(r['risk_score'] / 100)
    st.caption(r['note'])
    tab1, tab2, tab3 = st.tabs(['Explanation', 'URL inspection', 'Export report'])
    with tab1:
        if r['warning_signs']:
            for item in r['warning_signs']:
                st.write('Warning: ' + item)
        else:
            st.info('No configured warning pattern detected. This does not establish that the message is legitimate.')
        st.write('Never share OTPs or PINs. Verify through the official app or a phone number you independently know.')
    with tab2:
        if not r['url_inspection']:
            st.info('No explicit http(s) or www URL was detected.')
        for item in r['url_inspection']:
            with st.expander(item['url'], expanded=True):
                for finding in item['findings'] or ['No configured URL warning detected. This does not mean the destination is safe.']:
                    st.write('Warning: ' + finding if item['findings'] else finding)
        st.caption('The app does not visit URLs, follow redirects, or query live domain-reputation services.')
    with tab3:
        st.download_button('Download JSON report', json.dumps(r, indent=2), 'scamshield-analysis.json', 'application/json')
        st.download_button('Download text report', '\n'.join([f"Risk: {r['risk_level']}", f"Score: {r['risk_score']}/100", *r['warning_signs']]), 'scamshield-analysis.txt', 'text/plain')
st.divider()
st.caption('Educational prototype only. A low score is not proof of safety; a high score is not proof of fraud.')