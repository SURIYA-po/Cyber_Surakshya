import tempfile
from pathlib import Path

from inference import resolve_model_path


def test_resolve_model_path_prefers_existing_model_artifact() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "model.pkl").write_bytes(b"model")
        (tmp_path / "model_DNN.pkl").write_bytes(b"dnn")

        resolved = resolve_model_path(str(tmp_path))

        assert resolved == str(tmp_path / "model.pkl")
