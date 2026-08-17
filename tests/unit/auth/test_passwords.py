from zeroshield.auth.passwords import hash_password, verify_password


def test_hash_is_never_the_plaintext() -> None:
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"
    assert h.startswith("$argon2id$")


def test_verify_correct_password() -> None:
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h) is True


def test_verify_wrong_password_is_false_not_an_exception() -> None:
    h = hash_password("correct horse battery staple")
    assert verify_password("wrong password", h) is False


def test_two_hashes_of_the_same_password_differ() -> None:
    # Argon2 salts every hash - two hashes of the same plaintext must never
    # be byte-identical, or a database leak would reveal duplicate passwords.
    assert hash_password("same-password") != hash_password("same-password")
