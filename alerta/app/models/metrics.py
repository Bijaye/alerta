
import time
import json

from functools import wraps

from alerta.app import db


class MetricEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, o):
        return o.__dict__


class Gauge(object):

    def __init__(self, group, name, title=None, description=None, value=0):

        self.group = group
        self.name = name
        self.title = title
        self.description = description
        self.value = value

    def set(self, value):
        self.value = db.set_gauge(self.group, self.name, self.title, self.description, value)

    @property
    def serialize(self):
        return json.dumps(self, cls=MetricEncoder)

    @classmethod
    def get_gauges(cls, format=None):
        if format == 'json':
            return db.get_metrics(type='gauge')
        elif format == 'prometheus':
            gauges = list()
            for g in Gauge.get_gauges():
                gauges.append(
                    '# HELP alerta_{group}_{name} {description}\n'
                    '# TYPE alerta_{group}_{name} gauge\n'
                    'alerta_{group}_{name} {value}\n'.format(
                        group=g.group, name=g.name, description=g.description, value=g.value
                    )
                )
            return "".join(gauges)
        return db.get_gauges()


class Counter(object):

    def __init__(self, group, name, title=None, description=None, count=0):

        self.group = group
        self.name = name
        self.title = title
        self.description = description
        self.count = count

    def inc(self, count=1):
        self.count = db.inc_counter(self.group, self.name, self.title, self.description, count)

    @property
    def serialize(self):
        return json.dumps(self, cls=MetricEncoder)

    @classmethod
    def get_counters(cls, format=None):
        if format == 'json':
            return db.get_metrics(type='counter')
        elif format == 'prometheus':
            counters = list()
            for c in Counter.get_counters():
                counters.append(
                    '# HELP alerta_{group}_{name} {description}\n'
                    '# TYPE alerta_{group}_{name} counter\n'
                    'alerta_{group}_{name}_total {count}\n'.format(
                        group=c.group, name=c.name, description=c.description, count=c.count
                    )
                )
            return "".join(counters)
        return db.get_counters()


class Timer(object):

    def __init__(self, group, name, title=None, description=None, count=0, total_time=0):

        self.group = group
        self.name = name
        self.title = title
        self.description = description

        self.start = None
        self.count = count
        self.total_time = total_time

    @staticmethod
    def _time_in_millis():
        return int(round(time.time() * 1000))

    def start_timer(self):
        return self._time_in_millis()

    def stop_timer(self, start, count=1):

        now = self._time_in_millis()
        r = db.update_timer(self.group, self.name, self.title, self.description, count, duration=(now - start))
        self.count, self.total_time = r['count'], r['totalTime']

    @property
    def serialize(self):
        return json.dumps(self, cls=MetricEncoder)

    @classmethod
    def get_timers(cls, format=None):
        if format == 'json':
            return db.get_metrics(type='timer')
        elif format == 'prometheus':
            timers = list()
            for t in Timer.get_timers():
                timers.append(
                    '# HELP alerta_{group}_{name} {description}\n'
                    '# TYPE alerta_{group}_{name} summary\n'
                    'alerta_{group}_{name}_count {count}\n'
                    'alerta_{group}_{name}_sum {total_time}\n'.format(
                        group=t.group, name=t.name, description=t.description, count=t.count, total_time=t.total_time
                    )
                )
            return "".join(timers)
        return db.get_timers()


def timer(metric):
    def decorated(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ts = metric.start_timer()
            response = f(*args, **kwargs)
            metric.stop_timer(ts)
            return response
            # return f(*args, **kwargs)
        return wrapped
    return decorated
