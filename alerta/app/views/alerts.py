
from flask import jsonify, request, g
from flask_cors import cross_origin

from alerta.app.auth.utils import permission
from alerta.app.exceptions import RejectException, RateLimit, BlackoutPeriod
from alerta.app.models.alert import Alert
from alerta.app.models.metrics import Timer, timer
from alerta.app.utils.api import jsonp, process_alert, process_status, add_remote_ip
from alerta.app.exceptions import ApiError

from . import api

receive_timer = Timer('alerts', 'received', 'Received alerts', 'Total time and number of received alerts')
gets_timer = Timer('alerts', 'queries', 'Alert queries', 'Total time and number of alert queries')
status_timer = Timer('alerts', 'status', 'Alert status change', 'Total time and number of alerts with status changed')
tag_timer = Timer('alerts', 'tagged', 'Tagging alerts', 'Total time to tag number of alerts')
untag_timer = Timer('alerts', 'untagged', 'Removing tags from alerts', 'Total time to un-tag and number of alerts')
attrs_timer = Timer('alerts', 'attributes', 'Alert attributes change', 'Total time and number of alerts with attributes changed')
delete_timer = Timer('alerts', 'deleted', 'Deleted alerts', 'Total time and number of deleted alerts')
count_timer = Timer('alerts', 'counts', 'Count alerts', 'Total time and number of count queries')


@api.route('/alert', methods=['OPTIONS', 'POST'])
@cross_origin()
@permission('write:alerts')
@timer(receive_timer)
@jsonp
def receive():
    try:
        incomingAlert = Alert.parse(request.json)
    except ValueError as e:
        raise ApiError(str(e), 400)

    if g.get('customer', None):
        incomingAlert.customer = g.get('customer')

    add_remote_ip(request, incomingAlert)

    try:
        alert = process_alert(incomingAlert)
    except RejectException as e:
        raise ApiError(str(e), 403)
    except RateLimit as e:
        return jsonify(status="error", message=str(e), id=incomingAlert.id), 429
    except BlackoutPeriod as e:
        return jsonify(status="ok", message=str(e), id=incomingAlert.id), 202
    except Exception as e:
        raise ApiError(str(e), 500)

    if alert:
        return jsonify(status="ok", id=alert.id, alert=alert.serialize), 201
    else:
        raise ApiError("insert or update of received alert failed", 500)


@api.route('/alert/<alert_id>', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(gets_timer)
@jsonp
def get_alert(alert_id):
    customer = g.get('customer', None)
    alert = Alert.get(alert_id, customer)

    if alert:
        return jsonify(status="ok", total=1, alert=alert.serialize)
    else:
        raise ApiError("not found", 404)


# set status
@api.route('/alert/<alert_id>/status', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:alerts')
@timer(status_timer)
@jsonp
def set_status(alert_id):
    status = request.json.get('status', None)
    text = request.json.get('text', '')

    if not status:
        raise ApiError("must supply 'status' as json data")

    customer = g.get('customer', None)
    alert = Alert.get(alert_id, customer)

    if not alert:
        raise ApiError("not found", 404)

    try:
        alert, status, text = process_status(alert, status, text)
    except RejectException as e:
        raise ApiError(str(e), 403)
    except Exception as e:
        raise ApiError(str(e), 500)

    if alert.set_status(status, text):
        return jsonify(status="ok")
    else:
        raise ApiError("failed to set alert status", 500)


# tag
@api.route('/alert/<alert_id>/tag', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:alerts')
@timer(tag_timer)
@jsonp
def tag_alert(alert_id):
    if not request.json.get('tags', None):
        raise ApiError("must supply 'tags' as json list")

    customer = g.get('customer', None)
    alert = Alert.get(alert_id, customer)

    if not alert:
        raise ApiError("not found", 404)

    if alert.tag(tags=request.json['tags']):
        return jsonify(status="ok")
    else:
        raise ApiError("failed to tag alert", 500)


# untag
@api.route('/alert/<alert_id>/untag', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:alerts')
@timer(untag_timer)
@jsonp
def untag_alert(alert_id):
    if not request.json.get('tags', None):
        raise ApiError("must supply 'tags' as json list")

    customer = g.get('customer', None)
    alert = Alert.get(alert_id, customer)

    if not alert:
        raise ApiError("not found", 404)

    if alert.untag(tags=request.json['tags']):
        return jsonify(status="ok")
    else:
        raise ApiError("failed to untag alert", 500)


# update attributes
@api.route('/alert/<alert_id>/attributes', methods=['OPTIONS', 'PUT'])
@cross_origin()
@permission('write:alerts')
@timer(attrs_timer)
@jsonp
def update_attributes(alert_id):
    if not request.json.get('attributes', None):
        raise ApiError("must supply 'attributes' as json data", 400)

    customer = g.get('customer', None)
    alert = Alert.get(alert_id, customer)

    if not alert:
        raise ApiError("not found", 404)

    if alert.update_attributes(request.json['attributes']):
        return jsonify(status="ok")
    else:
        raise ApiError("failed to update attributes", 500)


# delete
@api.route('/alert/<alert_id>', methods=['OPTIONS', 'DELETE'])
@cross_origin()
@permission('write:alerts')
@timer(delete_timer)
@jsonp
def delete_alert(alert_id):
    customer = g.get('customer', None)
    alert = Alert.get(alert_id, customer)

    if not alert:
        raise ApiError("not found", 404)

    if alert.delete():
        return jsonify(status="ok")
    else:
        raise ApiError("failed to delete alert", 500)


@api.route('/alerts', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(gets_timer)
@jsonp
def search_alerts():
    query, sort, group, page, page_size, query_time = Alert.build_query(request.args)
    severity_count = Alert.get_counts_by_severity(query)
    status_count = Alert.get_counts_by_status(query)

    total = sum(severity_count.values())
    pages = ((total - 1) // page_size) + 1
    if total and page > pages or page < 0:
        raise ApiError("page out of range: 1-%s" % pages, 416)

    alerts = Alert.find_all(query, sort, page, page_size)

    if alerts:
        return jsonify(
            status="ok",
            total=total,
            page=page,
            pageSize=page_size,
            pages=pages,
            more=page < pages,
            alerts=[alert.serialize for alert in alerts],
            statusCounts=status_count,
            severityCounts=severity_count,
            lastTime=max([alert.last_receive_time for alert in alerts])
        )
    else:
        return jsonify(
            status="ok",
            message="not found",
            total=0,
            page=page,
            pageSize=page_size,
            pages=pages,
            more=False,
            alerts=[],
            severityCounts=severity_count,
            statusCounts=status_count,
            lastTime=query_time
        )


@api.route('/alerts/history', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(gets_timer)
@jsonp
def history():
    query, _, _, _, _, _ = Alert.build_query(request.args)
    history = Alert.get_history(query)

    if history:
        return jsonify(
            status="ok",
            history=history
        )
    else:
        raise ApiError('No alert histories found', 404)


# severity counts
# status counts
@api.route('/alerts/count', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(count_timer)
@jsonp
def get_counts():
    query, _, _, _, _, _ = Alert.build_query(request.args)
    severity_count = Alert.get_counts_by_severity(query)
    status_count = Alert.get_counts_by_status(query)

    return jsonify(
        status="ok",
        total=sum(severity_count.values()),
        severityCounts=severity_count,
        statusCounts=status_count
    )


# top 10 counts
@api.route('/alerts/top10/count', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(count_timer)
@jsonp
def get_top10_count():
    query, _, _, _, _, _ = Alert.build_query(request.args)
    top10 = Alert.get_top10_count(query)

    if top10:
        return jsonify(
            status="ok",
            total=len(top10),
            top10=top10
        )
    else:
        raise ApiError('No alerts found', 404)


# top 10 flapping
@api.route('/alerts/top10/flapping', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(count_timer)
@jsonp
def get_top10_flapping():
    query, _, _, _, _, _ = Alert.build_query(request.args)
    top10 = Alert.get_top10_flapping(query)

    if top10:
        return jsonify(
            status="ok",
            total=len(top10),
            top10=top10
        )
    else:
        raise ApiError('No flapping alerts found', 404)

# get alert environments
@api.route('/environments', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(gets_timer)
@jsonp
def get_environments():
    query, _, _, _, _, _ = Alert.build_query(request.args)
    environments = Alert.get_environments(query)

    if environments:
        return jsonify(
            status="ok",
            total=len(environments),
            environments=environments
        )
    else:
        raise ApiError('No environments found', 404)


# get alert services
@api.route('/services', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:alerts')
@timer(gets_timer)
@jsonp
def get_services():
    query, _, _, _, _, _ = Alert.build_query(request.args)
    services = Alert.get_services(query)

    if services:
        return jsonify(
            status="ok",
            total=len(services),
            services=services
        )
    else:
        raise ApiError('No services found', 404)
