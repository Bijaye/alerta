
from flask import jsonify, request, g
from flask_cors import cross_origin

from alerta.app.models.blackout import Blackout
from alerta.app.auth.utils import permission
from alerta.app.utils.api import jsonp, absolute_url
from alerta.app.exceptions import ApiError

from . import api


@api.route('/blackout', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission('write:blackouts')
@jsonp
def create_blackout():
    try:
        blackout = Blackout.parse(request.json)
    except Exception as e:
        raise ApiError(str(e), 400)

    if g.get('customer', None):
        blackout.customer = g.get('customer')

    try:
        blackout = blackout.create()
    except Exception as e:
        raise ApiError(str(e), 500)

    if blackout:
        return jsonify(status="ok", id=blackout.id, blackout=blackout.serialize), 201, {'Location': absolute_url('/blackout/' + blackout.id)}
    else:
        raise ApiError("insert blackout failed", 500)


@api.route('/blackouts', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:blackouts')
@jsonp
def list_blackouts():
    query = dict()
    if g.get('customer', None):
        query['customer'] = g.get('customer')

    blackouts = Blackout.find_all(query)

    if blackouts:
        return jsonify(
            status="ok",
            blackouts=[blackout.serialize for blackout in blackouts],
            total=len(blackouts)
        )
    else:
        raise ApiError('no blackouts found', 404)


@api.route('/blackout/<blackout_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:blackouts')
@jsonp
def delete_blackout(blackout_id):
    customer = g.get('customer', None)
    blackout = Blackout.get(blackout_id, customer)

    if not blackout:
        raise ApiError("not found", 404)

    if blackout.delete():
        return jsonify(status="ok")
    else:
        raise ApiError("failed to delete blackout", 500)
