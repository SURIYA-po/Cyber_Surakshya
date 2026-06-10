# IDS FastAPI Demo

This workspace adds a minimal FastAPI backend and a tiny frontend to run inference
using the existing `inference.py` utilities.

Quick start (local):

1. Create a Python environment and install dependencies:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

2. Place your model artifacts in a folder and set `ARTIFACT_DIR` env var (or create `./artifacts`):

- `model.pkl`
- `scaler.pkl`
- `label_encoder.pkl`
- `feature_columns.json`

3. Run the app:

```bash
set ARTIFACT_DIR=C:\path\to\artifacts  # Windows
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

4. Open `http://localhost:8000/` to use the simple frontend, or call the endpoints:

- `POST /predict` JSON
- `POST /predict/csv` (file)
- `POST /predict/zeek` (Zeek conn.log upload)
# Final_year_project_prototype
This is the final year project on cyber security integration AI for automation for detection ,analysis and response agents working parallely for faster threat and vulnerarabitlty detection and quick response 
