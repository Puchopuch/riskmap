import pytest

from riskmap.scanner import validate_target


@pytest.mark.parametrize("target", ["192.168.242.128", "192.168.1.0/24", "10.0.0.0/8"])
def test_valid_targets_are_accepted(target):
    validate_target(target)  # must not raise


@pytest.mark.parametrize("target", ["--script=/tmp/evil.nse", "127.0.0.1; rm -rf ~", "999.1.1.1", "example.com", ""])
def test_invalid_targets_are_refused(target):
    with pytest.raises(ValueError):
        validate_target(target)
