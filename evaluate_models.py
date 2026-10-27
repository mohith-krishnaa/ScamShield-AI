"""Compare baseline text classifiers on the illustrative starter dataset."""
from pathlib import Path
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

ROOT = Path(__file__).resolve().parent
def main():
    df = pd.read_csv(ROOT / 'data' / 'messages.csv').dropna(subset=['text', 'label'])
    X_train, X_test, y_train, y_test = train_test_split(df.text, df.label, test_size=.25, random_state=42, stratify=df.label)
    models = {'Logistic Regression': LogisticRegression(max_iter=1500, class_weight='balanced', random_state=42), 'Multinomial Naive Bayes': MultinomialNB(), 'Linear SVM': LinearSVC(random_state=42)}
    for name, classifier in models.items():
        pipeline = Pipeline([('tfidf', TfidfVectorizer(ngram_range=(1, 2), lowercase=True, strip_accents='unicode')), ('classifier', classifier)])
        pipeline.fit(X_train, y_train)
        pred = pipeline.predict(X_test)
        print(f"\n{name}")
        print(f"Accuracy: {accuracy_score(y_test, pred):.3f} | Scam precision: {precision_score(y_test, pred, pos_label='scam', zero_division=0):.3f} | Scam recall: {recall_score(y_test, pred, pos_label='scam', zero_division=0):.3f} | Scam F1: {f1_score(y_test, pred, pos_label='scam', zero_division=0):.3f}")
    print('\nCaution: results on this small hand-written dataset are illustrative, not real-world performance estimates.')
if __name__ == '__main__':
    main()
