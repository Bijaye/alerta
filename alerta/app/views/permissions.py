
from flask import jsonify, request, g
from flask_cors import cross_origin

from alerta.app.auth.utils import permission
from alerta.app.models.permission import Permission
from alerta.app.utils.api import jsonp
from alerta.app.exceptions import ApiError

from . import api


@api.route('/perm', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission('admin:perms')
@jsonp
def create_perm():
    try:
        perm = Permission.parse(request.json)
    except ValueError as e:
        raise ApiError(str(e), 400)

    for want_scope in perm.scopes:
        if not Permission.is_in_scope(want_scope, g.scopes):
            raise ApiError("Requested scope '%s' not in existing scopes: %s" % (want_scope, ','.join(g.scopes)), 403)

    try:
        perm = perm.create()
    except Exception as e:
        raise ApiError(str(e), 500)

    if perm:
        return jsonify(status="ok", id=perm.id, permission=perm.serialize), 201
    else:
        raise ApiError("create API key failed", 500)


@api.route('/perms', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:perms')
@jsonp
def list_perms():
    perms = Permission.find_all()

    if perms:
        return jsonify(
            status="ok",
            total=len(perms),
            permissions=[perm.serialize for perm in perms]
        )
    else:
        raise ApiError('No permissions found', 404)


@api.route('/perm/<perm_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('admin:perms')
@jsonp
def delete_perm(perm_id):
    perm = Permission.get(perm_id)

    if not perm:
        raise ApiError("not found", 404)

    if perm.delete():
        return jsonify(status="ok")
    else:
        raise ApiError("failed to delete permission", 500)
