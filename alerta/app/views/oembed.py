
from flask import request, render_template, jsonify, current_app
from flask_cors import cross_origin

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from alerta.app import db
from alerta.app.models.alert import Alert
from alerta.app.auth.utils import permission
from alerta.app.utils.api import jsonp


from . import api

#LOG = app.logger

@api.route('/oembed', defaults={'format':'json'}, methods=['OPTIONS', 'GET'])
@api.route('/oembed.<format>', methods=['OPTIONS', 'GET'])
@cross_origin()
@permission('read:oembed')
@jsonp
def oembed(format):

    if format != 'json':
        return jsonify(status="error", message="unsupported format: %s" % format), 400

    if 'url' not in request.args or 'maxwidth' not in request.args \
            or 'maxheight' not in request.args:
        return jsonify(status="error", message="missing default parameters: url, maxwidth, maxheight"), 400

    try:
        url = request.args['url']
        width = int(request.args['maxwidth'])
        height = int(request.args['maxheight'])
        title = request.args.get('title', 'Alerts')
    except Exception as e:
        return jsonify(status="error", message=str(e)), 400

    try:
        o = urlparse(url)
        query, _, _, _, _, _ = Alert.build_query(request.args)
    except Exception as e:
        return jsonify(status="error", message=str(e)), 500

    if o.path.endswith('/alerts/count'):
        try:
            severity_count = db.get_counts(query=query, fields={"severity": 1}, group="severity")
        except Exception as e:
            return jsonify(status="error", message=str(e)), 500

        max = 'normal'
        if severity_count.get('warning', 0) > 0:
            max = 'warning'
        if severity_count.get('minor', 0) > 0:
            max = 'minor'
        if severity_count.get('major', 0) > 0:
            max = 'major'
        if severity_count.get('critical', 0) > 0:
            max = 'critical'

        html = render_template(
            'oembed/counts.html',
            title=title,
            width=width,
            height=height,
            max=max,
            counts=severity_count
        )
        return jsonify(version="1.0", type="rich", width=width, height=height, title=title, provider_name="Alerta", provider_url=request.url_root, html=html)

    elif o.path.endswith('/alerts/top10/count'):
        # TODO: support top10 oembed widget
        pass
    else:
        return jsonify(status="error", message="unsupported oEmbed URL scheme"), 400


@api.route('/embed.js', methods=['OPTIONS', 'GET'])
def embed_js():

    return current_app.send_static_file('embed.js')