# 🛡️ ScamShield AI — Scam Message & URL Risk Analyzer

**ScamShield AI** is a local-first academic PBL prototype that analyzes pasted SMS messages, emails, chat messages, and URL text. It combines a supervised NLP baseline with explainable pattern checks and produces a downloadable analysis report.

> **Safety and evaluation notice:** This project is an educational prototype, not a security product. The included dataset is small, hand-written, and illustrative. Its high scores do **not** estimate real-world performance. A high score is not proof of fraud, and a low score is not proof of safety.

## Features

- **NLP classifier:** TF-IDF word/phrase features with Logistic Regression.
- **Explainable indicators:** credential/OTP requests, urgency, prize bait, payment pressure, generic greetings, secrecy requests, and other patterns.
- **URL syntax inspection:** checks for HTTP-only links, IP hosts, `@` authority tricks, punycode labels, long hostnames, many subdomains, shorteners, caution-listed TLDs, and executable-looking paths.
- **Transparent demonstration score:** capped model signal plus warning indicators; not a calibrated probability.
- **Dashboard:** result summary, explanation, URL inspection, session history, and downloadable JSON, TXT, and CSV exports.
- **Privacy-minded processing:** no external AI API; the application does not open URLs or query live threat-intelligence feeds.
- **Evaluation scripts:** held-out split, model comparison, confusion matrices, scam precision/recall/F1, and false-negative rate.
- **Tests and documentation:** unit tests, project report, architecture/test plan, dataset card, viva questions, and presentation deck.

## Technology stack

- Python 3.10+
- Streamlit
- pandas
- scikit-learn (TF-IDF, Logistic Regression, Naive Bayes, Linear SVM)
- joblib
- Python standard library

## Run locally

From the project directory:

```bash
python -m venv .venv
```

**Windows:**
```bat
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python train_model.py
python evaluate_models.py
python -m unittest discover -s tests -v
streamlit run app.py
```

**macOS / Linux:**
```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python train_model.py
python evaluate_models.py
python -m unittest discover -s tests -v
streamlit run app.py
```

The trained model is generated locally and intentionally excluded from source control; run `python train_model.py` before launching the app.

## Project structure

- `app.py` — Streamlit dashboard
- `analyzer.py` — explainable text and URL indicators
- `train_model.py` — trains the baseline model
- `evaluate_models.py` — compares baseline classifiers
- `data/messages.csv` — small illustrative labelled dataset
- `tests/` — unit tests
- `PROJECT_REPORT.md` — PBL report draft
- `ARCHITECTURE_AND_TEST_PLAN.md` — architecture and test cases
- `DATASET_CARD.md` — dataset provenance and limitations
- `VIVA_QUESTIONS.md` — viva preparation
- `presentation.pptx` — presentation deck

## Evaluation limitations

The starter CSV contains 80 hand-written illustrative rows. A stratified 75/25 split leaves 60 training rows and 20 test rows. Perfect scores on this small dataset are not reliable evidence of real-world detection performance. Replace or supplement it with a documented, appropriately licensed, diverse dataset and evaluate on a held-out test set before making performance claims.

## Privacy and safe use

- Do not paste real OTPs, passwords, recovery codes, card details, or private information.
- No external AI API is called by this prototype.
- The app does not visit URLs, follow redirects, inspect page content, or query a live threat feed.
- Treat findings as prompts for careful verification, not as legal, financial, or cybersecurity guarantees.

## PBL objectives

1. Apply NLP text vectorization using TF-IDF.
2. Train and compare supervised classifiers.
3. Explain model output with transparent rule-based indicators.
4. Build an interactive application with report export.
5. Evaluate model behavior and document limitations, privacy, and ethical use.

## License

MIT. See [LICENSE](LICENSE).