
import psycopg2 as pg
from datetime import datetime

from flask import current_app
from psycopg2.extras import NamedTupleCursor, register_composite
from psycopg2.extensions import register_adapter, adapt, AsIs


class Backend:

    def __init__(self, app=None):
        self.app = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        backend = 'postgres'

        self.app = app
        if backend not in app.extensions:
            app.extensions[backend] = {}
        app.extensions[backend] = self.connect(app.config)

    def connect(self, config):
        # > createdb alerta
        conn = pg.connect(
            database='alerta5',
            host='localhost',
            port=5432,
            user='postgres',
            password='postgres',
            cursor_factory=NamedTupleCursor
        )

        self.register_history(conn)
        return conn

    def register_history(self, conn):
        from alerta.app.models.alert import History
        register_composite(
            'history',
            conn,
            globally=True
        )

        def adapt_history(h):
            return AsIs("(%s::uuid, %s, %s, %s, %s, %s, %s, %s)::history" % (
                    adapt(h.id),
                    adapt(h.event),
                    adapt(str(h.severity)),
                    adapt(str(h.status)),
                    adapt(h.value),
                    adapt(h.event_type),
                    adapt(h.text),
                    adapt(h.update_time)
            ))

        register_adapter(History, adapt_history)

    def close(self):
        self.conn.close()

    @property
    def conn(self):
        return current_app.extensions['postgres']

    ########################################

    def is_duplicate(self, alert):
        query = """SELECT id FROM alerts
            WHERE environment=%(environment)s
              AND resource=%(resource)s
              AND event=%(event)s
              AND severity=%(severity)s
            """
        if alert.customer:
            query += " AND CUSTOMER=%(customer)s"
        cursor = self.conn.cursor()
        cursor.execute(query, vars(alert))
        return bool(cursor.fetchone())

    def is_correlated(self, alert):
        query = """SELECT id FROM alerts
            WHERE environment=%(environment)s
              AND resource=%(resource)s
              AND ((event=%(event)s AND severity!=%(severity)s) OR (event!=%(event)s AND %(event)s=ANY(correlate)))
        """
        if alert.customer:
            query += " AND CUSTOMER=%(customer)s"
        cursor = self.conn.cursor()
        cursor.execute(query, vars(alert))
        return bool(cursor.fetchone())

    def dedup_alert(self, alert):
        print('dedup %s' % alert)

    def correlate_alert(self, alert):
        print('corelate %s' % alert)

        now = datetime.utcnow()
        update = """UPDATE alerts
        SET event='%s', severity='%s', status='%s', value='%s', text='%s', create_time='%s', raw_data='%s',
            duplicate_count=0, repeat=false, previous_severity='%s', trend_indication='%s', receive_time='%s',
            last_receive_id='%s', last_receive_time='%s'
        WHERE environment='%s'
              AND resource='%s'
              AND ((event='%s' AND severity!='%s') OR (event!='%s' AND '%s'=ANY(correlate)))
        """ % (
            alert.event,
            alert.severity,
            alert.status,  # FIXME
            alert.group,
            alert.text,
            alert.create_time,
            alert.raw_data,
            alert.previous_severity,  # FIXME
            alert.trend_indication,  # FIXME
            now,
            alert.id,
            now,
            alert.environment,
            alert.resource,
            alert.event,
            alert.severity,
            alert.event,
            alert.event
        )
        cursor = self.conn.cursor()
        cursor.execute(update)
        return self.conn.commit()

    def save_alert(self, alert):
        try:
            insert = """
                INSERT INTO alerts (id, resource, event, environment, severity, correlate, status, service, "group",
                    value, text, tags, attributes, origin, type, create_time, timeout, raw_data, customer,
                    duplicate_count, repeat, previous_severity, trend_indication, receive_time, last_receive_id,
                    last_receive_time, history)
                VALUES ( %(id)s, %(resource)s, %(event)s, %(environment)s, %(severity)s, %(correlate)s, %(status)s,
                    %(service)s, %(group)s, %(value)s, %(text)s, %(tags)s, %(attributes)s , %(origin)s,
                    %(event_type)s, %(create_time)s, %(timeout)s, %(raw_data)s, %(customer)s, %(duplicate_count)s,
                    %(repeat)s, %(previous_severity)s, %(trend_indication)s, %(receive_time)s, %(last_receive_id)s,
                    %(last_receive_time)s, %(history)s::history[] )
            """

            data = vars(alert)
            data['attributes'] = [list(a) for a in alert.attributes.items()]
            cursor = self.conn.cursor()
            # from alerta.app.models.alert import History
            # register_composite('history', self.conn)
            cursor.execute(insert, data)
            #print(cursor.mogrify(insert, data))

            from uuid import uuid4
            from psycopg2.extras import register_uuid
            register_uuid()
            print(cursor.mogrify("""SELECT %s, %s, %s;""", (None, datetime.utcnow(), uuid4())))


        except Exception as e:
            print(e)
        return self.conn.commit()

    def find_alert_by_id(self, id, customer=None):
        query = "SELECT * FROM alerts WHERE id=%(id)s"
        if customer:
            query += " AND CUSTOMER=%(customer)s"
        cursor = self.conn.cursor()
        cursor.execute(query, {'id': id, 'customer': customer})
        return cursor.fetchone()

    def find_alerts_by_query(self, query=None, fields=None, page=1, limit=0):
        # FIXME: build query, fields, sort from query and limit history
        query = """SELECT * FROM alerts OFFSET %s LIMIT %s"""
        cursor = self.conn.cursor()
        cursor.execute(query, ((page - 1) * limit, limit))
        return cursor.fetchall()

    def get_counts_by_severity(self, query=None):
        query = """SELECT severity, COUNT(*) FROM alerts GROUP BY severity"""
        cursor = self.conn.cursor()
        cursor.execute(query)
        return dict([(s.severity, s.count) for s in cursor.fetchall()])

    def get_counts_by_status(self, query=None):
        query = """SELECT status, COUNT(*) FROM alerts GROUP BY status"""
        cursor = self.conn.cursor()
        cursor.execute(query)
        return dict([(s.status, s.count) for s in cursor.fetchall()])

