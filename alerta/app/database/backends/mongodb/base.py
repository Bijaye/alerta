import json
import pytz
import re

from datetime import datetime, timedelta
from flask import current_app, g

from pymongo import MongoClient, ASCENDING, TEXT, ReturnDocument
from pymongo.errors import ConnectionFailure

from alerta.app.models import status_code
from alerta.app.utils.format import DateTime
from alerta.app import severity
from alerta.app.exceptions import NoCustomerMatch, ApiError

# See https://github.com/MongoEngine/flask-mongoengine/blob/master/flask_mongoengine/__init__.py
# See https://github.com/dcrosta/flask-pymongo/blob/master/flask_pymongo/__init__.py


class Backend:

    def connect(self, config):

        conn = MongoClient(config.get('MONGO_URI', 'mongodb://localhost:27017/monitoring'))

        if config.get('MONGO_DATABASE', None):
            db = conn[config['MONGO_DATABASE']]
        else:
            db = conn.get_database()

        # create unique indexes
        db.alerts.create_index(
            [('environment', ASCENDING), ('customer', ASCENDING), ('resource', ASCENDING), ('event', ASCENDING)],
            unique=True
        )
        db.alerts.create_index([('$**', TEXT)])
        db.heartbeats.create_index([('origin', ASCENDING), ('customer', ASCENDING)], unique=True)
        db.metrics.create_index([('group', ASCENDING), ('name', ASCENDING)], unique=True)

        return conn, db

    @property
    def cx(self):
        return current_app.extensions['mongodb'][0]

    @property
    def db(self):
        return current_app.extensions['mongodb'][1]

    @property
    def version(self):
        return self.db.client.server_info()['version']

    @property
    def is_alive(self):
        try:
            self.db.client.admin.command('ismaster')
        except ConnectionFailure:
            return False
        return True

    def close(self):
        self.db.close()

    def destroy(self, name=None):
        name = name or self.db.name
        self.cx.drop_database(name)

    def build_query(self, params):

        query_time = datetime.utcnow()

        # q
        if params.get('q', None):
            query = json.loads(params.pop('q'))
        else:
            query = dict()

        # customer
        if g.get('customer', None):
            query['customer'] = g.get('customer')

        # from-date, to-date
        from_date = params.get('from-date', default=None, type=DateTime.parse)
        to_date = params.get('to-date', default=query_time, type=DateTime.parse)

        if from_date and to_date:
            query['lastReceiveTime'] = {'$gt': from_date.replace(tzinfo=pytz.utc), '$lte': to_date.replace(tzinfo=pytz.utc)}
        elif to_date:
            query['lastReceiveTime'] = {'$lte': to_date.replace(tzinfo=pytz.utc)}

        # duplicateCount, repeat
        if params.get('duplicateCount', None):
            query['duplicateCount'] = params.get('duplicateCount', int)
        if params.get('repeat', None):
            query['repeat'] = params.get('repeat', default=True, type=lambda x: x == 'true')

        # sort-by
        sort = list()
        direction = 1
        if params.get('reverse', None):
            direction = -1
        if params.get('sort-by', None):
            for sort_by in params.getlist('sort-by'):
                if sort_by in ['createTime', 'receiveTime', 'lastReceiveTime']:
                    sort.append((sort_by, -direction))  # reverse chronological
                else:
                    sort.append((sort_by, direction))
        else:
            sort.append(('lastReceiveTime', -direction))

        # group-by
        group = params.getlist('group-by')

        # page, page-size, limit (deprecated)
        page = params.get('page', 1, int)
        limit = params.get('limit', current_app.config['DEFAULT_PAGE_SIZE'], int)
        page_size = params.get('page-size', limit, int)

        # id
        ids = params.getlist('id')
        if len(ids) == 1:
            query['$or'] = [{'_id': {'$regex': '^' + ids[0]}}, {'lastReceiveId': {'$regex': '^' + ids[0]}}]
        elif ids:
            query['$or'] = [{'_id': {'$regex': re.compile('|'.join(['^' + i for i in ids]))}},
                            {'lastReceiveId': {'$regex': re.compile('|'.join(['^' + i for i in ids]))}}]

        EXCLUDE_QUERY = ['q', 'id', 'from-date', 'to-date', 'repeat', 'sort-by', 'reverse', 'group-by', 'page', 'page-size', 'limit']

        # fields
        for field in params:
            if field in EXCLUDE_QUERY:
                continue
            value = params.getlist(field)
            if len(value) == 1:
                value = value[0]
                if field.endswith('!'):
                    if value.startswith('~'):
                        query[field[:-1]] = dict()
                        query[field[:-1]]['$not'] = re.compile(value[1:], re.IGNORECASE)
                    else:
                        query[field[:-1]] = dict()
                        query[field[:-1]]['$ne'] = value
                else:
                    if value.startswith('~'):
                        query[field] = dict()
                        query[field]['$regex'] = re.compile(value[1:], re.IGNORECASE)
                    else:
                        query[field] = value
            else:
                if field.endswith('!'):
                    if '~' in [v[0] for v in value]:
                        value = '|'.join([v.lstrip('~') for v in value])
                        query[field[:-1]] = dict()
                        query[field[:-1]]['$not'] = re.compile(value, re.IGNORECASE)
                    else:
                        query[field[:-1]] = dict()
                        query[field[:-1]]['$nin'] = value
                else:
                    if '~' in [v[0] for v in value]:
                        value = '|'.join([v.lstrip('~') for v in value])
                        query[field] = dict()
                        query[field]['$regex'] = re.compile(value, re.IGNORECASE)
                    else:
                        query[field] = dict()
                        query[field]['$in'] = value

        return query, sort, group, page, page_size, query_time

    #### ALERTS

    def get_severity(self, alert):
        """
        Get severity of correlated alert. Used to determine previous severity.
        """
        query = {
            "environment": alert.environment,
            "resource": alert.resource,
            '$or': [
                {
                    "event": alert.event,
                    "severity": {'$ne': alert.severity}
                },
                {
                    "event": {'$ne': alert.event},
                    "correlate": alert.event
                }],
            "customer": alert.customer
        }
        return self.db.alerts.find_one(query, projection={"severity": 1, "_id": 0})['severity']

    def get_status(self, alert):
        """
        Get status of correlated or duplicate alert. Used to determine previous status.
        """
        query = {
            "environment": alert.environment,
            "resource": alert.resource,
            '$or': [
                {
                    "event": alert.event
                },
                {
                    "correlate": alert.event,
                }
            ],
            "customer": alert.customer
        }
        return self.db.alerts.find_one(query, projection={"status": 1, "_id": 0})['status']

    def is_duplicate(self, alert):
        query = {
            "environment": alert.environment,
            "resource": alert.resource,
            "event": alert.event,
            "severity": alert.severity,
            "customer": alert.customer
        }
        return bool(self.db.alerts.find_one(query))

    def is_correlated(self, alert):
        query = {
            "environment": alert.environment,
            "resource": alert.resource,
            '$or': [
                {
                    "event": alert.event,
                    "severity": {'$ne': alert.severity}
                },
                {
                    "event": {'$ne': alert.event},
                    "correlate": alert.event
                }],
            "customer": alert.customer
        }
        return bool(self.db.alerts.find_one(query))

    def is_flapping(self, alert, window=1800, count=2):
        """
        Return true if alert severity has changed more than X times in Y seconds
        """
        pipeline = [
            {'$match': {"environment": alert.environment, "resource": alert.resource, "event": alert.event}},
            {'$unwind': '$history'},
            {'$match': {
                "history.updateTime": {'$gt': datetime.utcnow() - timedelta(seconds=window)}},
                "history.type": "severity"
            },
            {
                '$group': {
                    "_id": '$history.type',
                    "count": {'$sum': 1}
                }
            }
        ]
        responses = self.db.alerts.aggregate(pipeline)
        for r in responses:
            if r['count'] > count:
                return True
        return False

    def dedup_alert(self, alert):
        """
        Update alert value, text and rawData, increment duplicate count and set repeat=True, and
        keep track of last receive id and time but don't append to history unless status changes.
        """
        previous_status = self.get_status(alert)
        if alert.status != status_code.UNKNOWN and alert.status != previous_status:
            status = alert.status
        else:
            status = status_code.status_from_severity(alert.severity, alert.severity, previous_status)

        query = {
            "environment": alert.environment,
            "resource": alert.resource,
            "event": alert.event,
            "severity": alert.severity,
            "customer": alert.customer
        }

        now = datetime.utcnow()
        update = {
            '$set': {
                "status": status,
                "value": alert.value,
                "text": alert.text,
                "rawData": alert.raw_data,
                "repeat": True,
                "lastReceiveId": alert.id,
                "lastReceiveTime": now
            },
            '$addToSet': {"tags": {'$each': alert.tags}},
            '$inc': {"duplicateCount": 1}
        }

        # only update those attributes that are specifically defined
        attributes = {'attributes.'+k: v for k, v in alert.attributes.items()}
        update['$set'].update(attributes)

        if status != previous_status:
            update['$push'] = {
                "history": {
                    '$each': [{
                        "event": alert.event,
                        "status": status,
                        "type": "status",
                        "text": "duplicate alert status change",
                        "id": alert.id,
                        "updateTime": now
                    }],
                    '$slice': -abs(current_app.config['HISTORY_LIMIT'])
                }
            }

        return self.db.alerts.find_one_and_update(
            query,
            update=update,
            projection={"history": 0},
            return_document=ReturnDocument.AFTER
        )

    def correlate_alert(self, alert):
        """
        Update alert key attributes, reset duplicate count and set repeat=False, keep track of last
        receive id and time, appending all to history. Append to history again if status changes.
        """
        previous_severity = self.get_severity(alert)
        previous_status = self.get_status(alert)
        trend_indication = severity.trend(previous_severity, alert.severity)
        if alert.status == status_code.UNKNOWN:
            status = status_code.status_from_severity(previous_severity, alert.severity, previous_status)
        else:
            status = alert.status

        query = {
            "environment": alert.environment,
            "resource": alert.resource,
            '$or': [
                {
                    "event": alert.event,
                    "severity": {'$ne': alert.severity}
                },
                {
                    "event": {'$ne': alert.event},
                    "correlate": alert.event
                }],
            "customer": alert.customer
        }

        now = datetime.utcnow()
        update = {
            '$set': {
                "event": alert.event,
                "severity": alert.severity,
                "status": status,
                "value": alert.value,
                "text": alert.text,
                "createTime": alert.create_time,
                "rawData": alert.raw_data,
                "duplicateCount": 0,
                "repeat": False,
                "previousSeverity": previous_severity,
                "trendIndication": trend_indication,
                "receiveTime": now,
                "lastReceiveId": alert.id,
                "lastReceiveTime": now
            },
            '$addToSet': {"tags": {'$each': alert.tags}},
            '$push': {
                "history": {
                    '$each': [{
                        "event": alert.event,
                        "severity": alert.severity,
                        "value": alert.value,
                        "type": "severity",
                        "text": alert.text,
                        "id": alert.id,
                        "updateTime": now
                    }],
                    '$slice': -abs(current_app.config['HISTORY_LIMIT'])
                }
            }
        }

        # only update those attributes that are specifically defined
        attributes = {'attributes.'+k: v for k, v in alert.attributes.items()}
        update['$set'].update(attributes)

        if status != previous_status:
            update['$push']['history']['$each'].append({
                "event": alert.event,
                "status": status,
                "type": "status",
                "text": "correlated alert status change",
                "id": alert.id,
                "updateTime": now
            })

        return self.db.alerts.find_one_and_update(
            query,
            update=update,
            projection={"history": 0},
            return_document=ReturnDocument.AFTER
        )

    def create_alert(self, alert):
        data = {
            "_id": alert.id,
            "resource": alert.resource,
            "event": alert.event,
            "environment": alert.environment,
            "severity": alert.severity,
            "correlate": alert.correlate,
            "status": alert.status,
            "service": alert.service,
            "group": alert.group,
            "value": alert.value,
            "text": alert.text,
            "tags": alert.tags,
            "attributes": alert.attributes,
            "origin": alert.origin,
            "type": alert.event_type,
            "createTime": alert.create_time,
            "timeout": alert.timeout,
            "rawData": alert.raw_data,
            "customer": alert.customer,
            "duplicateCount": alert.duplicate_count,
            "repeat": alert.repeat,
            "previousSeverity": alert.previous_severity,
            "trendIndication": alert.trend_indication,
            "receiveTime": alert.receive_time,
            "lastReceiveId": alert.last_receive_id,
            "lastReceiveTime": alert.last_receive_time,
            "history": [h.serialize for h in alert.history]
        }
        if self.db.alerts.insert_one(data).inserted_id == alert.id:
            return data

    def get_alert(self, id, customer=None):
        if len(id) == 8:
            query = {'$or': [{'_id': {'$regex': '^' + id}}, {'lastReceiveId': {'$regex': '^' + id}}]}
        else:
            query = {'$or': [{'_id': id}, {'lastReceiveId': id}]}

        if customer:
            query['customer'] = customer

        return self.db.alerts.find_one(query)

    #### STATUS, TAGS, ATTRIBUTES

    def set_status(self, id, status, text=None):
        """
        Set status and update history.
        """
        query = {'_id': {'$regex': '^' + id}}

        event = self.db.alerts.find_one(query, projection={"event": 1, "_id": 0})['event']
        if not event:
            return False

        now = datetime.utcnow()
        update = {
            '$set': {"status": status},
            '$push': {
                "history": {
                    '$each': [{
                        "event": event,
                        "status": status,
                        "type": "status",
                        "text": text,
                        "id": id,
                        "updateTime": now
                    }],
                    '$slice': -abs(current_app.config['HISTORY_LIMIT'])
                }
            }
        }
        return self.db.alerts.find_one_and_update(
            query,
            update=update,
            projection={"history": 0},
            return_document=ReturnDocument.AFTER
        )

    def tag_alert(self, id, tags):
        """
        Append tags to tag list. Don't add same tag more than once.
        """
        response = self.db.alerts.update_one({'_id': {'$regex': '^' + id}}, {'$addToSet': {"tags": {'$each': tags}}})
        return response.matched_count > 0

    def untag_alert(self, id, tags):
        """
        Remove tags from tag list.
        """
        response = self.db.alerts.update_one({'_id': {'$regex': '^' + id}}, {'$pullAll': {"tags": tags}})
        return response.matched_count > 0

    def update_attributes(self, id, attrs):
        """
        Set all attributes (including private attributes) and unset attributes by using a value of 'null'.
        """
        update = dict()
        set_value = {'attributes.' + k: v for k, v in attrs.items() if v is not None}
        if set_value:
            update['$set'] = set_value
        unset_value = {'attributes.' + k: v for k, v in attrs.items() if v is None}
        if unset_value:
            update['$unset'] = unset_value

        response = self.db.alerts.update_one({'_id': {'$regex': '^' + id}}, update=update)
        return response.matched_count > 0

    def delete_alert(self, id):
        response = self.db.alerts.delete_one({'_id': {'$regex': '^' + id}})
        return True if response.deleted_count == 1 else False

    #### SEARCH & HISTORY

    def get_alerts(self, query=None, sort=None, page=1, page_size=0):
        return self.db.alerts.find(query, sort=sort).skip((page-1)*page_size).limit(page_size)

    def get_history(self, query=None, fields=None):

        if not fields:
            fields = {
                "resource": 1,
                "event": 1,
                "environment": 1,
                "customer": 1,
                "service": 1,
                "group": 1,
                "tags": 1,
                "attributes": 1,
                "origin": 1,
                "type": 1,
                "history": 1
            }

        pipeline = [
            {'$match': query},
            {'$unwind': '$history'},
            {'$project': fields},
            {'$limit': current_app.config['HISTORY_LIMIT']},
            {'$sort': {'history.updateTime': 1}}
        ]

        responses = self.db.alerts.aggregate(pipeline)

        history = list()
        for response in responses:
            if 'severity' in response['history']:
                history.append(
                    {
                        "id": response['_id'],  # or response['history']['id']
                        "resource": response['resource'],
                        "event": response['history']['event'],
                        "environment": response['environment'],
                        "severity": response['history']['severity'],
                        "service": response['service'],
                        "group": response['group'],
                        "value": response['history']['value'],
                        "text": response['history']['text'],
                        "tags": response['tags'],
                        "attributes": response['attributes'],
                        "origin": response['origin'],
                        "updateTime": response['history']['updateTime'],
                        "type": response['history'].get('type', 'unknown'),
                        "customer": response.get('customer', None)
                    }
                )
            elif 'status' in response['history']:
                history.append(
                    {
                        "id": response['_id'],  # or response['history']['id']
                        "resource": response['resource'],
                        "event": response['event'],
                        "environment": response['environment'],
                        "status": response['history']['status'],
                        "service": response['service'],
                        "group": response['group'],
                        "text": response['history']['text'],
                        "tags": response['tags'],
                        "attributes": response['attributes'],
                        "origin": response['origin'],
                        "updateTime": response['history']['updateTime'],
                        "type": response['history'].get('type', 'unknown'),
                        "customer": response.get('customer', None)
                    }
                )
        return history

    #### COUNTS

    def get_count(self, query=None):
        """
        Return total number of alerts that meet the query filter.
        """
        return self.db.alerts.find(query).count()

    def get_counts(self, query=None, fields=None, group=None):
        pipeline = [
            {'$match': query},
            {'$project': fields or {}},
            {'$group': {"_id": "$" + group, "count": {'$sum': 1}}}
        ]
        responses = self.db.alerts.aggregate(pipeline)

        counts = dict()
        for response in responses:
            counts[response['_id']] = response['count']
        return counts

    def get_counts_by_severity(self, query=None):
        return self.get_counts(query, fields={"severity": 1}, group="severity")

    def get_counts_by_status(self, query=None):
        return self.get_counts(query, fields={"status": 1}, group="status")

    def get_topn_count(self, query=None, group="event", topn=10):

        pipeline = [
            {'$match': query},
            {'$unwind': '$service'},
            {
                '$group': {
                    "_id": "$%s" % group,
                    "count": {'$sum': 1},
                    "duplicateCount": {'$sum': "$duplicateCount"},
                    "environments": {'$addToSet': "$environment"},
                    "services": {'$addToSet': "$service"},
                    "resources": {'$addToSet': {"id": "$_id", "resource": "$resource"}}
                }
            },
            {'$sort': {"count": -1, "duplicateCount": -1}},
            {'$limit': topn}
        ]

        responses = self.db.alerts.aggregate(pipeline)

        top = list()
        for response in responses:
            top.append(
                {
                    "%s" % group: response['_id'],
                    "environments": response['environments'],
                    "services": response['services'],
                    "resources": response['resources'],
                    "count": response['count'],
                    "duplicateCount": response['duplicateCount']
                }
            )
        return top

    def get_topn_flapping(self, query=None, group="event", topn=10):
        pipeline = [
            {'$match': query},
            {'$unwind': '$service'},
            {'$unwind': '$history'},
            {'$match': {"history.type": "severity"}},
            {
                '$group': {
                    "_id": "$%s" % group,
                    "count": {'$sum': 1},
                    "duplicateCount": {'$max': "$duplicateCount"},
                    "environments": {'$addToSet': "$environment"},
                    "services": {'$addToSet': "$service"},
                    "resources": {'$addToSet': {"id": "$_id", "resource": "$resource"}}
                }
            },
            {'$sort': {"count": -1, "duplicateCount": -1}},
            {'$limit': topn}
        ]

        responses = self.db.alerts.aggregate(pipeline)

        top = list()
        for response in responses:
            top.append(
                {
                    "%s" % group: response['_id'],
                    "environments": response['environments'],
                    "services": response['services'],
                    "resources": response['resources'],
                    "count": response['count'],
                    "duplicateCount": response['duplicateCount']
                }
            )
        return top

    #### ENVIRONMENTS

    def get_environments(self, query=None, topn=100):
        pipeline = [
            {'$match': query},
            {'$project': {"environment": 1}},
            {'$limit': topn},
            {'$group': {"_id": "$environment", "count": {'$sum': 1}}}
        ]
        responses = self.db.alerts.aggregate(pipeline)

        environments = list()
        for response in responses:
            environments.append(
                {
                    "environment": response['_id'],
                    "count": response['count']
                }
            )
        return environments

    #### SERVICES

    def get_services(self, query=None, topn=100):
        pipeline = [
            {'$unwind': '$service'},
            {'$match': query},
            {'$project': {"environment": 1, "service": 1}},
            {'$limit': topn},
            {'$group': {"_id": {"environment": "$environment", "service": "$service"}, "count": {'$sum': 1}}}
        ]
        responses = self.db.alerts.aggregate(pipeline)

        services = list()
        for response in responses:
            services.append(
                {
                    "environment": response['_id']['environment'],
                    "service": response['_id']['service'],
                    "count": response['count']
                }
            )
        return services

    #### BLACKOUTS

    def create_blackout(self, blackout):
        data = {
            "_id": blackout.id,
            "priority": blackout.priority,
            "environment": blackout.environment,
            "startTime": blackout.start_time,
            "endTime": blackout.end_time,
            "duration": blackout.duration
        }
        if blackout.service:
            data["service"] = blackout.service
        if blackout.resource:
            data["resource"] = blackout.resource
        if blackout.event:
            data["event"] = blackout.event
        if blackout.group:
            data["group"] = blackout.group
        if blackout.tags:
            data["tags"] = blackout.tags
        if blackout.customer:
            data["customer"] = blackout.customer

        if self.db.blackouts.insert_one(data).inserted_id == blackout.id:
            return data

    def get_blackout(self, id, customer=None):
        query = {'_id': id}
        if customer:
            query['customer'] = customer
        return self.db.blackouts.find_one(query)

    def get_blackouts(self, query=None, page=1, page_size=0):
        return self.db.blackouts.find(query).skip((page - 1) * page_size).limit(page_size)

    def is_blackout_period(self, alert):
        now = datetime.utcnow()

        query = dict()
        query['startTime'] = {'$lte': now}
        query['endTime'] = {'$gt': now}

        query['environment'] = alert.environment
        query['$or'] = [
            {
                "resource": {'$exists': False},
                "service": {'$exists': False},
                "event": {'$exists': False},
                "group": {'$exists': False},
                "tags": {'$exists': False}
            },
            {
                "resource": alert.resource,
                "service": {'$exists': False},
                "event": {'$exists': False},
                "group": {'$exists': False},
                "tags": {'$exists': False}
            },
            {
                "resource": {'$exists': False},
                "service": {"$not": {"$elemMatch": {"$nin": alert.service}}},
                "event": {'$exists': False},
                "group": {'$exists': False},
                "tags": {'$exists': False}
            },
            {
                "resource": {'$exists': False},
                "service": {'$exists': False},
                "event": alert.event,
                "group": {'$exists': False},
                "tags": {'$exists': False}
            },
            {
                "resource": {'$exists': False},
                "service": {'$exists': False},
                "event": {'$exists': False},
                "group": alert.group,
                "tags": {'$exists': False}
            },
            {
                "resource": alert.resource,
                "service": {'$exists': False},
                "event": alert.event,
                "group": {'$exists': False},
                "tags": {'$exists': False}
            },
            {
                "resource": {'$exists': False},
                "service": {'$exists': False},
                "event": {'$exists': False},
                "group": {'$exists': False},
                "tags": {"$not": {"$elemMatch": {"$nin": alert.tags}}}
            }
        ]

        if self.db.blackouts.find_one(query):
            return True
        if current_app.config['CUSTOMER_VIEWS']:
            query['customer'] = alert.customer
            if self.db.blackouts.find_one(query):
                return True
        return False

    def delete_blackout(self, id):
        response = self.db.blackouts.delete_one({"_id": id})
        return True if response.deleted_count == 1 else False

    #### HEARTBEATS

    def upsert_heartbeat(self, heartbeat):
        return self.db.heartbeats.find_one_and_update(
            {
                "origin": heartbeat.origin,
                "customer": heartbeat.customer
            },
            {
                '$setOnInsert': {
                    "_id": heartbeat.id
                },
                '$set': {
                    "origin": heartbeat.origin,
                    "tags": heartbeat.tags,
                    "type": heartbeat.event_type,
                    "createTime": heartbeat.create_time,
                    "timeout": heartbeat.timeout,
                    "receiveTime": heartbeat.receive_time,
                    "customer": heartbeat.customer
                }
            },
            upsert=True,
            return_document=ReturnDocument.AFTER
        )

    def get_heartbeat(self, id, customer=None):
        if len(id) == 8:
            query = {'_id': {'$regex': '^' + id}}
        else:
            query = {'_id': id}

        if customer:
            query['customer'] = customer

        return self.db.heartbeats.find_one(query)

    def get_heartbeats(self, query=None, page=1, page_size=0):
        return self.db.heartbeats.find(query).skip((page - 1) * page_size).limit(page_size)

    def delete_heartbeat(self, id):
        response = self.db.heartbeats.delete_one({'_id': {'$regex': '^' + id}})
        return True if response.deleted_count == 1 else False

    #### API KEYS

    # save
    def create_key(self, key):
        data = {
            "_id": key.key,
            "user": key.user,
            "scopes": key.scopes,
            "text": key.text,
            "expireTime": key.expire_time,
            "count": key.count,
            "lastUsedTime": key.last_used_time
        }
        if key.customer:
            data['customer'] = key.customer

        if self.db.keys.insert_one(data).inserted_id == key.key:
            return data

    # get
    def get_key(self, key, customer=None):
        query = {'$or': [{'key': key}, {'_id': key}]}
        if customer:
            query['customer'] = customer
        return self.db.keys.find_one(query)

    # list
    def get_keys(self, query=None, page=1, page_size=0):
        return self.db.keys.find(query).skip((page - 1) * page_size).limit(page_size)

    # update
    def update_key_last_used(self, key):
        return self.db.keys.update_one(
            {'$or': [{'key': key}, {'_id': key}]},
            {
                '$set': {"lastUsedTime": datetime.utcnow()},
                '$inc': {"count": 1}
            }
        ).matched_count == 1

    # delete
    def delete_key(self, key):
        query = {'$or': [{'key': key}, {'_id': key}]}
        response = self.db.keys.delete_one(query)
        return True if response.deleted_count == 1 else False

    #### USERS

    def create_user(self, user):
        data = {
            "_id": user.id,
            "name": user.name,
            "password": user.password,
            "email": user.email,
            "createTime": user.create_time,
            "lastLogin": user.last_login,
            "text": user.text,
            "email_verified": user.email_verified
        }
        if self.db.users.insert_one(data).inserted_id == user.id:
            return data

    # get
    def get_user(self, id, customer=None):
        query = {'_id': id}
        if customer:
            query['customer'] = customer
        return self.db.users.find_one(query)

    # list
    def get_users(self, query=None, page=1, page_size=0):
        return self.db.users.find(query).skip((page - 1) * page_size).limit(page_size)

    def get_user_by_email(self, email):
        query = {"email": email}
        return self.db.users.find_one(query)

    def get_user_by_hash(self, hash):
        query = {"hash": hash}
        return self.db.users.find_one(query)

    def get_user_password(self, id):
        return

    def update_last_login(self, id):
        return self.db.users.update_one(
            {"_id": id},
            update={'$set': {"lastLogin": datetime.utcnow()}}
        ).matched_count == 1

    def set_email_hash(self, id, hash):
        return self.db.users.update_one(
            {"_id": id},
            update={'$set': {'hash': hash, 'updateTime': datetime.utcnow()}}
        ).matched_count == 1

    def update_user(self, id, **kwargs):
        return self.db.users.find_one_and_update(
            {"_id": id},
            update={'$set': kwargs},
            return_document=ReturnDocument.AFTER
        )

    def delete_user(self, id):
        response = self.db.users.delete_one({"_id": id})
        return True if response.deleted_count == 1 else False


    #### PERMISSIONS

    def create_perm(self, perm):
        data = {
            "_id": perm.id,
            "match": perm.match,
            "scopes": perm.scopes
        }
        if self.db.perms.insert_one(data).inserted_id == perm.id:
            return data

    def get_perm(self, id):
        query = {'_id': id}
        return self.db.perms.find_one(query)

    def get_perms(self, query=None, page=1, page_size=0):
        return self.db.perms.find(query).skip((page - 1) * page_size).limit(page_size)

    def delete_perm(self, id):
        response = self.db.perms.delete_one({"_id": id})
        return True if response.deleted_count == 1 else False

    def get_scopes_by_match(self, login, matches):
        if login in current_app.config['ADMIN_USERS']:
            return ['admin', 'read', 'write']

        scopes = list()
        for match in matches:
            response = self.db.perms.find_one({"match": match}, projection={"scopes": 1, "_id": 0})
            if response:
                scopes.extend(response['scopes'])
        return set(scopes) or current_app.config['USER_DEFAULT_SCOPES']

    #### CUSTOMERS

    def create_customer(self, customer):
        data = {
            "_id": customer.id,
            "match": customer.match,
            "customer": customer.customer
        }
        if self.db.customers.insert_one(data).inserted_id == customer.id:
            return data

    def get_customer(self, id):
        query = {'_id': id}
        return self.db.customers.find_one(query)

    def get_customers(self, query=None, page=1, page_size=0):
        return self.db.customers.find(query).skip((page - 1) * page_size).limit(page_size)

    def delete_customer(self, id):
        response = self.db.customers.delete_one({"_id": id})
        return True if response.deleted_count == 1 else False

    def get_customers_by_match(self, login, matches):
        if login in current_app.config['ADMIN_USERS']:
            return '*'  # all customers
        for match in [login] + matches:
            response = self.db.customers.find_one({"match": match}, projection={"customer": 1, "_id": 0})
            if response:
                return response['customer']
        raise NoCustomerMatch("No customer lookup configured for user '%s' or '%s'" % (login, ','.join(matches)))

    #### METRICS

    def get_metrics(self, type=None):

        query = {"type": type} if type else {}
        return list(self.db.metrics.find(query, {"_id": 0}))

    def set_gauge(self, group, name, title=None, description=None, value=0):

        return self.db.metrics.find_one_and_update(
            {
                "group": group,
                "name": name
            },
            {
                '$set': {
                    "group": group,
                    "name": name,
                    "title": title,
                    "description": description,
                    "value": value,
                    "type": "gauge"
                }
            },
            upsert=True,
            return_document=ReturnDocument.AFTER
        )['value']

    def get_gauges(self):
        from alerta.app.models.metrics import Gauge
        return [
            Gauge(
                group=g.get('group'),
                name=g.get('name'),
                title=g.get('title', ''),
                description=g.get('description', ''),
                value=g.get('value', 0)
            ) for g in self.db.metrics.find({"type": "gauge"}, {"_id": 0})
        ]

    def inc_counter(self, group, name, title=None, description=None, count=1):

        return self.db.metrics.find_one_and_update(
            {
                "group": group,
                "name": name
            },
            {
                '$set': {
                    "group": group,
                    "name": name,
                    "title": title,
                    "description": description,
                    "type": "counter"
                },
                '$inc': {"count": count}
            },
            upsert=True,
            return_document=ReturnDocument.AFTER
        )['count']

    def get_counters(self):
        from alerta.app.models.metrics import Counter
        return [
            Counter(
                group=c.get('group'),
                name=c.get('name'),
                title=c.get('title', ''),
                description=c.get('description', ''),
                count=c.get('count', 0)
            ) for c in self.db.metrics.find({"type": "counter"}, {"_id": 0})
        ]

    def update_timer(self, group, name, title=None, description=None, count=1, duration=0):
        return self.db.metrics.find_one_and_update(
            {
                "group": group,
                "name": name
            },
            {
                '$set': {
                    "group": group,
                    "name": name,
                    "title": title,
                    "description": description,
                    "type": "timer"
                },
                '$inc': {"count": count, "totalTime": duration}
            },
            upsert=True,
            return_document=ReturnDocument.AFTER
        )

    def get_timers(self):
        from alerta.app.models.metrics import Timer
        return [
            Timer(
                group=t.get('group'),
                name=t.get('name'),
                title=t.get('title', ''),
                description=t.get('description', ''),
                count=t.get('count', 0),
                total_time=t.get('totalTime', 0)
            ) for t in self.db.metrics.find({"type": "timer"}, {"_id": 0})
        ]
