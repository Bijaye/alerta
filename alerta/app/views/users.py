
from flask import jsonify, request, g, current_app
from flask_cors import cross_origin

from alerta.app.models.user import User
from alerta.app.auth.utils import permission
from alerta.app.utils.api import jsonp, absolute_url
from alerta.app.exceptions import ApiError

from . import api

# NOTE: "user create" method is basic auth "sign up" method


@api.route('/user/<user_id>', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('admin:users')
@jsonp
def update_user(user_id):
    if not request.json:
        raise ApiError("nothing to change", 400)

    customer = g.get('customer', None)
    user = User.get(user_id, customer)

    if not user:
        raise ApiError("not found", 404)

    if user.update(**request.json):
        return jsonify(status="ok")
    else:
        raise ApiError("failed to update user", 500)


@api.route('/users', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:users')
@jsonp
def list_users():
    if 'admin' in g.scopes or 'admin:users' in g.scopes:
        users = User.find_all()
    else:
        users = User.get(g.user, g.customer)

    if users:
        return jsonify(
            status="ok",
            total=len(users),
            users=[user.serialize for user in users],
            domains=current_app.config['ALLOWED_EMAIL_DOMAINS'],
            orgs=current_app.config['ALLOWED_GITHUB_ORGS'],
            groups=current_app.config['ALLOWED_GITLAB_GROUPS'],
            roles=current_app.config['ALLOWED_KEYCLOAK_ROLES'],
        )
    else:
        raise ApiError('no users found', 404)


@api.route('/user/<user_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:users')
@jsonp
def delete_user(user_id):
    customer = g.get('customer', None)
    user = User.get(user_id, customer)

    if not user:
        raise ApiError("not found", 404)

    if user.delete():
        return jsonify(status="ok")
    else:
        raise ApiError("failed to delete user", 500)
