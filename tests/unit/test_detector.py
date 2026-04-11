import pytest
from unittest.mock import patch, MagicMock
from backend.detector import _human, _parse_size, _manufacturer, DeviceDetectionError


def test_human_bytes_gb():
    assert "1.0 GB" == _human(1024 ** 3)


def test_human_bytes_tb():
    assert "1.0 TB" == _human(1024 ** 4)


def test_human_bytes_mb():
    assert "512.0 MB" == _human(512 * 1024 ** 2)


def test_parse_size_gigabytes():
    assert _parse_size("1G") == 1024 ** 3


def test_parse_size_terabytes():
    assert _parse_size("2T") == 2 * 1024 ** 4


def test_parse_size_numeric():
    assert _parse_size("1073741824") == 1073741824


def test_parse_size_invalid():
    assert _parse_size("invalid") == 0


def test_manufacturer_samsung():
    assert _manufacturer("Samsung 870 EVO") == "Samsung"


def test_manufacturer_wd():
    assert _manufacturer("WDC WD10EZEX") == "WDC"


def test_manufacturer_seagate():
    assert _manufacturer("Seagate Barracuda") == "Seagate"


def test_manufacturer_unknown():
    result = _manufacturer("XYZ Unknown Drive")
    assert result == "XYZ"


def test_detect_raises_when_no_devices():
    with patch("backend.detector.SYSTEM", "Linux"), \
         patch("backend.detector._detect_linux", return_value=[]):
        with pytest.raises(DeviceDetectionError):
            from backend.detector import detect_devices
            detect_devices()
