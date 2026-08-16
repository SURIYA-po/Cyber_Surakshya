"""Direct model access: score JSON, a CSV, or a Zeek conn.log.

These bypass the agent pipeline and return raw predictions.
"""
from __future__ import annotations

import io
from typing import Any

import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from api.runtime import ensure_runtime, platform
from inference import predict, predict_zeek_log

router = APIRouter(tags=["prediction"])


@router.post("/predict")
async def predict_json(payload: dict[str, Any]):
    ensure_runtime()
    if platform.artifacts is None and platform.model is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    if isinstance(payload, dict) and "records" in payload:
        records = payload["records"]
    elif isinstance(payload, dict) and any(isinstance(v, (int, float, str)) for v in payload.values()):
        records = [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        raise HTTPException(status_code=400, detail="Invalid payload format for prediction")

    df = pd.DataFrame.from_records(records)
    arts = platform.artifacts or (platform.model, platform.scaler, platform.label_encoder, platform.feature_columns)
    results = predict(df, arts, return_proba=True)
    out = results.reset_index(drop=True).to_dict(orient="records")
    return JSONResponse(content={"predictions": out})


@router.post("/predict/csv")
async def predict_csv_upload(file: UploadFile = File(...)):
    ensure_runtime()
    if platform.artifacts is None and platform.model is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")
    arts = platform.artifacts or (platform.model, platform.scaler, platform.label_encoder, platform.feature_columns)
    results = predict(df, arts, return_proba=True)
    out_df = pd.concat([df.reset_index(drop=True), results.reset_index(drop=True)], axis=1)
    return JSONResponse(content={"predictions": out_df.to_dict(orient="records")})


@router.post("/predict/zeek")
async def predict_zeek(file: UploadFile = File(...)):
    ensure_runtime()
    if platform.artifacts is None and platform.model is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    try:
        contents = (await file.read()).decode("utf-8")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp:
            tmp.write(contents)
            tmp.flush()
            arts = platform.artifacts or (platform.model, platform.scaler, platform.label_encoder, platform.feature_columns)
            res = predict_zeek_log(tmp.name, output_path=None, artifacts=arts)
        return JSONResponse(content={"predictions": res.reset_index(drop=True).to_dict(orient="records")})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Zeek prediction failed: {e}")
