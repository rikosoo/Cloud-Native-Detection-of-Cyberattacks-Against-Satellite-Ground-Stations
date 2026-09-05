import pytest

from gsd.detection.engine import DetectionEngine
from gsd.detection.ml import fit_from_events
from gsd.simulator.scenario import run_scenario

MINUTES = 12 * 60


@pytest.fixture(scope="session")
def baseline():
    return run_scenario(minutes=MINUTES, seed=43, attacks=[])


@pytest.fixture(scope="session")
def model(baseline):
    return fit_from_events(baseline.events)


@pytest.fixture(scope="session")
def attacked():
    return run_scenario(minutes=MINUTES, seed=42)


@pytest.fixture(scope="session")
def findings(attacked, model):
    return DetectionEngine(model=model).run(attacked.events)
