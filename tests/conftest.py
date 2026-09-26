import pytest

from app.config import MODEL_PATH


@pytest.fixture(scope="session", autouse=True)
def ensure_model():
    if not MODEL_PATH.exists():
        from app.training import train_and_save
        train_and_save(verbose=False)


@pytest.fixture(scope="session")
def analyzer():
    from app.analyzer import get_analyzer
    return get_analyzer()
