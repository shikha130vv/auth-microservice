import json


def test_new_user_registration(test_client, init_database):
    """
    GIVEN a Flask application
    WHEN the '/' page is is posted to (POST)
    THEN check that a '405' status code is returned
    """
    response = test_client.post('/auth/register',
                                data=json.dumps(dict(
                                    email='newuser@gmail.com',
                                    password='password')),
                                follow_redirects=True,
                                content_type='application/json'
                                )
    assert response.get_json().get("message") == "Successfully registered."
    assert response.status_code == 201


def test_existing_user_registration(test_client, init_database):
    """
    GIVEN a Flask application
    WHEN the '/' page is is posted to (POST)
    THEN check that a '405' status code is returned
    """
    response = test_client.post('/auth/register',
                                data=json.dumps(dict(
                                    email='existinguser@gmail.com',
                                    password='password')),
                                follow_redirects=True,
                                content_type='application/json'
                                )
    assert response.get_json().get("message") == "Successfully registered."
    assert response.status_code == 201
    response = test_client.post('/auth/register',
                                data=json.dumps(dict(
                                    email='existinguser@gmail.com',
                                    password='password')),
                                follow_redirects=True,
                                content_type='application/json'
                                )
    assert response.get_json().get("message") == "User already exists. Please Log in."
    assert response.status_code == 202


def test_existing_user_login(test_client, init_database):
    """
    GIVEN a Flask application
    WHEN the '/' page is is posted to (POST)
    THEN check that a '405' status code is returned
    """
    response = test_client.post('/auth/register',
                                data=json.dumps(dict(
                                    email='existingloginuser@gmail.com',
                                    password='password')),
                                follow_redirects=True,
                                content_type='application/json'
                                )
    assert response.get_json().get("message") == "Successfully registered."
    assert response.status_code == 201
    response = test_client.post('/auth/login',
                                data=json.dumps(dict(
                                    email='existingloginuser@gmail.com',
                                    password='password')),
                                follow_redirects=True,
                                content_type='application/json'
                                )
    assert response.data == b"You are logged in!"
    assert response.status_code == 200
