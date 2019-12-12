from flask import (request, jsonify, render_template,
                   make_response, redirect)
from flask.views import MethodView
from project.models import User, BlacklistToken, db, bcrypt
from . import auth_blueprint


class RegisterAPI(MethodView):
    def post(self):
        # get the post data
        post_data = request.get_json()
        email = post_data.get('email')
        password = post_data.get('password')
        # check if user already exists
        user = User.query.filter_by(email=email).first()
        if not user:
            try:
                user = User(
                    email=email,
                    password=password
                )
                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                response_object = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(response_object), 201)
            except Exception as e:
                response_object = {
                    'status': 'fail',
                    'message': 'Error:{}'.format(str(e))
                }
                return make_response(jsonify(response_object), 401)
        else:
            response_object = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(response_object), 202)


class LoginAPI(MethodView):
    def get(self):
        return make_response(render_template("login.html"))

    def post(self):
        # get the post data
        post_data = request.get_json()
        if post_data:
            email = post_data.get("email")
            password = post_data.get("password")
        else:
            email = request.form["email"] # "abc@g.com"
            password = request.form["password"]  # "pwd"  #
        rd = request.args.get("rd")
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=email
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, password
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    if rd:
                        redir = redirect(rd)
                    else:
                        redir = "You are logged in!"
                    response = make_response(redir)
                    response.set_cookie(
                        "Authorization", "Bearer {}".format(
                            auth_token.decode()))
                    return response
                    # return make_response(jsonify(responseObject)), 200
            else:
                if user is None:
                    response_object = {
                        'status': 'fail',
                        'message': 'User {} does not exist.'.format(email)
                    }
                else:
                    response_object = {
                        'status': 'fail',
                        'message': 'Please enter correct password.'
                    }
                return make_response(jsonify(response_object), 404)
        except Exception as e:
            print(e)
            response_object = {
                'status': 'fail',
                'message': 'Error:{}'.format(str(e))
            }
            return make_response(jsonify(response_object), 500)


class LogoutAPI(MethodView):
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    response_object = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(response_object), 200)
                except Exception as e:
                    response_object = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(response_object), 200)
            else:
                response_object = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(response_object), 401)
        else:
            response_object = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response_object), 403)


class AuthorizeAPI(MethodView):
    def get(self):
        # get auth token
        auth_json = jsonify({"status": "authorised"})
        unauth_json = jsonify({"status": "Unauthorized"})
        auth_header = request.cookies.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = None
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                try:
                    return make_response(auth_json, 200)
                except Exception as e:
                    return make_response(unauth_json, 401)
        return make_response(unauth_json, 401)


registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
authorize_view = AuthorizeAPI.as_view('authorize_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['GET', 'POST']
)
auth_blueprint.add_url_rule(
    '/auth/authorize',
    view_func=authorize_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
