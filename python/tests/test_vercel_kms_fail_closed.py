"""Regression: VercelKMSProvider must refuse to construct until its contract is verified live."""

import pathlib
import sys

import pytest

_BENCH = pathlib.Path(__file__).resolve().parents[2] / "benchmarks" / "agent-verification"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

from asymmetric_kms_provider import AsymmetricKMSUnavailableError, VercelKMSProvider


def test_vercel_kms_provider_refuses_construction():
    with pytest.raises(AsymmetricKMSUnavailableError, match="disabled"):
        VercelKMSProvider(issuer_id="iss_test", key_id="key_test")
