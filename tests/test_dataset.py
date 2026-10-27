"""Lightweight data and model smoke tests; run with: python -m unittest discover -s tests"""
import sys
import unittest
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

class StarterDatasetTests(unittest.TestCase):
    def test_dataset_has_required_columns_and_both_labels(self):
        df = pd.read_csv(ROOT / "data" / "messages.csv")
        self.assertTrue({"text", "label"}.issubset(df.columns))
        self.assertGreaterEqual(len(df), 20)
        self.assertEqual(set(df["label"].dropna().str.lower()), {"scam", "legitimate"})
        self.assertTrue(df["text"].dropna().astype(str).str.strip().ne("").all())

if __name__ == "__main__":
    unittest.main()
