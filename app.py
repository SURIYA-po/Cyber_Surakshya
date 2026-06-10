from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import io
import json
import pandas as pd
from typing import List, Dict, Any

# Reuse existing inference utilities
from inference import load_artifacts, predict, predict_csv, predict_zeek_log


ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "./artifacts")

app = FastAPI(title="IDS Inference API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_load():
    global MODEL, SCALER, LE, FEATURE_COLS
    try:
        MODEL, SCALER, LE, FEATURE_COLS = load_artifacts(
            os.path.join(ARTIFACT_DIR, "model.pkl"),
            os.path.join(ARTIFACT_DIR, "scaler.pkl"),
            os.path.join(ARTIFACT_DIR, "label_encoder.pkl"),
            os.path.join(ARTIFACT_DIR, "feature_columns.json"),
        )
    except Exception as e:
        MODEL, SCALER, LE, FEATURE_COLS = None, None, None, None
        print(f"[WARN] Could not load artifacts at startup: {e}")


@app.get("/health")
def health():
    ok = MODEL is not None and SCALER is not None and LE is not None and FEATURE_COLS is not None
    return {"status": "ok" if ok else "unavailable", "artifacts_loaded": ok}


@app.post("/predict")
async def predict_json(payload: Dict[str, Any]):
    """Predict from JSON payload. Accepts either a single record (dict) or list of records under `records` key."""
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")

    # Accept payload formats
    if isinstance(payload, dict) and "records" in payload:
        records = payload["records"]
    elif isinstance(payload, dict) and any(isinstance(v, (int, float, str)) for v in payload.values()):
        records = [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        raise HTTPException(status_code=400, detail="Invalid payload format for prediction")

    df = pd.DataFrame.from_records(records)
    results = predict(df, MODEL, SCALER, LE, FEATURE_COLS, return_proba=True)
    out = results.reset_index(drop=True).to_dict(orient="records")
    return JSONResponse(content={"predictions": out})


@app.post("/predict/csv")
async def predict_csv_upload(file: UploadFile = File(...)):
    """Upload a CSV file of flow features and get predictions."""
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")

    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")

    results = predict(df, MODEL, SCALER, LE, FEATURE_COLS, return_proba=True)
    out_df = pd.concat([df.reset_index(drop=True), results.reset_index(drop=True)], axis=1)
    # return JSON representation
    return JSONResponse(content={"predictions": out_df.to_dict(orient="records")})


@app.post("/predict/zeek")
async def predict_zeek(file: UploadFile = File(...)):
    """Upload a Zeek conn.log (text) file and get translated predictions."""
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")

    try:
        contents = (await file.read()).decode("utf-8")
        # write to temp buffer and call the existing helper by saving to a temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp:
            tmp.write(contents)
            tmp.flush()
            res = predict_zeek_log(tmp.name, MODEL, SCALER, LE, FEATURE_COLS)
        return JSONResponse(content={"predictions": res.reset_index(drop=True).to_dict(orient="records")})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Zeek prediction failed: {e}")


# Serve a minimal frontend if present
if os.path.isdir("frontend"):
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
