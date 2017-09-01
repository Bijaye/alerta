
import six
import datetime

from flask import json


class DateEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%S') + ".%03dZ" % (o.microsecond // 1000)
        else:
            return json.JSONEncoder.default(self, o)


class DateTime(object):

    @staticmethod
    def parse(date_str):
        if not isinstance(date_str, six.string_types):
            return
        try:
            return datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        except Exception:
            raise ValueError('dates must be ISO 8601 date format YYYY-MM-DDThh:mm:ss.sssZ')
