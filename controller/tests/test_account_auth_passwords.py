import importlib

import pytest


def test_argon2_password_bounds_and_nonblocking_admission():
    passwords = importlib.import_module("c2hunter_controller.auth_passwords")
    service = passwords.Passwords()
    secret = "Not normalized é!"
    encoded = service.hash(secret)
    assert encoded.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert service.verify(encoded, secret)
    assert not service.verify(encoded, secret + "x")
    assert not service.verify(None, secret)
    for invalid in ["short", "x" * 129, "\ud800" * 12]:
        with pytest.raises(passwords.PasswordError):
            service.hash(invalid)
    with service.slot(), service.slot(), pytest.raises(passwords.PasswordBusy):
        service.hash(secret)
    assert service.verify(encoded, secret)
