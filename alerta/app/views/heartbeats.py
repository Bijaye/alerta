
from flask import jsonify, request, g
from flask_cors import cross_origin

from alerta.app.auth.utils import permission
from alerta.app.models.heartbeat import Heartbeat
from alerta.app.utils.api import jsonp
from alerta.app.exceptions import ApiError

from . import api


@api.route('/heartbeat', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission('write:heartbeats')
@jsonp
def create_heartbeat():
    try:
        heartbeat = Heartbeat.parse(request.json)
    except ValueError as e:
        raise ApiError(str(e), 400)

    if g.get('customer', None):
        heartbeat.customer = g.get('customer')

    try:
        heartbeat = heartbeat.create()
    except Exception as e:
        raise ApiError(str(e), 500)

    if heartbeat:
        return jsonify(status="ok", id=heartbeat.id, heartbeat=heartbeat.serialize), 201
    else:
        raise ApiError("insert or update of received heartbeat failed", 500)


@api.route('/heartbeat/<heartbeat_id>', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:heartbeats')
@jsonp
def get_heartbeat(heartbeat_id):
    customer = g.get('customer', None)
    heartbeat = Heartbeat.get(heartbeat_id, customer)

    if heartbeat:
        return jsonify(status="ok", total=1, heartbeat=heartbeat.serialize)
    else:
        raise ApiError("not found", 404)


@api.route('/heartbeats', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:heartbeats')
@jsonp
def list_heartbeats():
    customer = g.get('customer', None)
    query = {'customer': customer}
    heartbeats = Heartbeat.find_all(query)

    if heartbeats:
        return jsonify(
            status="ok",
            total=len(heartbeats),
            heartbeats=[heartbeat.serialize for heartbeat in heartbeats]
        )
    else:
        raise ApiError('No heartbeats found', 404)


@api.route('/heartbeat/<heartbeat_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:heartbeats')
@jsonp
def delete_heartbeat(heartbeat_id):
    customer = g.get('customer', None)
    heartbeat = Heartbeat.get(heartbeat_id, customer)

    if not heartbeat:
        raise ApiError("not found", 404)

    if heartbeat.delete():
        return jsonify(status="ok")
    else:
        raise ApiError("failed to delete heartbeat", 500)
