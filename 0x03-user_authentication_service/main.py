#!/usr/bin/env python3
"""
Main file
End-to-end integration test for a user authentication service app
"""

import requests

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

BASE_URL = "http://localhost:5000"


def register_user(email, password):
    """
    Register a new user.
    """
    url = "{}/users".format(BASE_URL)
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}


def log_in_wrong_password(email, password):
    """
    Attempt to log in with the wrong password.
    """
    url = "{}/sessions".format(BASE_URL)
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 401


def log_in(email, password):
    """
    Log in with the correct credentials and return the session ID.
    """
    url = "{}/sessions".format(BASE_URL)
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "logged in"}
    assert "session_id" in response.cookies
    return response.cookies.get("session_id")


def profile_unlogged():
    """
    Attempt to access the profile without a valid session.
    """
    url = "{}/profile".format(BASE_URL)
    response = requests.get(url)
    assert response.status_code == 403


def profile_logged(session_id):
    """
    Access the profile with a valid session.
    """
    url = "{}/profile".format(BASE_URL)
    cookies = {"session_id": session_id}
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200
    assert response.json() == {"email": "guillaume@holberton.io"}


def log_out(session_id: str) -> None:
    """ Test for validating log out endpoint """
    cookies = {
        "session_id": session_id
    }
    url = '{}/sessions'.format(BASE_URL)
    response = requests.delete(url, cookies=cookies)

    expected_response = {"message": "Bienvenue"}

    assert response.status_code == 200
    assert response.json() == expected_response


def reset_password_token(email: str) -> str:
    """ Test for validating password reset token """
    data = {
        "email": email
    }
    url = '{}/reset_password'.format(BASE_URL)
    response = requests.post(url, data=data)

    assert response.status_code == 200

    reset_token = response.json().get("reset_token")

    expected_response = {"email": email, "reset_token": reset_token}

    assert response.json() == expected_response

    return reset_token


def update_password(email, reset_token, new_password):
    """
    Update the password using the reset token.
    """
    url = "{}/reset_password".format(BASE_URL)
    data = {"email": email, "reset_token":
            reset_token, "new_password": new_password}
    response = requests.put(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
