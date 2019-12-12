import pytest
from project import create_app, db
from project.models import User


@pytest.fixture(scope='module')
def new_user():
    user = User(email='abc@def.com', password='password')
    return user


@pytest.fixture(scope='session')
def test_client():
    flask_app, db = create_app('../config/flask_test.cfg')

    # Flask provides a way to test your application by exposing the Werkzeug test Client
    # and handling the context locals for you.
    testing_client = flask_app.test_client()

    # Establish an application context before running the tests.
    ctx = flask_app.app_context()
    ctx.push()

    yield testing_client  # this is where the testing happens!

    ctx.pop()


@pytest.fixture(scope='session')
def init_database():
    # Create the database and the database table

    db.create_all()

    yield db  # this is where the testing happens!

    db.session.close()
    db.drop_all()

