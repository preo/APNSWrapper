# Copyright 2009-2011 Max Klymyshyn, Sonettic
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


__all__ = ['APNSAlert', 'APNSNotificationWrapper', 'APNSNotification']

import struct
import base64
import binascii
import datetime
import decimal
try:
    import simplejson as json
except ImportError:
    import json

from .connection import APNSConnection
from .apnsexceptions import (APNSValueError, APNSTypeError,
                             APNSUndefinedDeviceToken, APNSPayloadLengthError)


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime.datetime) or isinstance(o, datetime.date):
            return o.isoformat()
        if isinstance(o, decimal.Decimal):
            return float(o)
        if hasattr(o, '__json__'):
            return o.__json__()
        return json.JSONEncoder.default(self, o)


def encode_json(data):
    return JSONEncoder(indent=None, separators=(',', ':')).encode(data)


class APNSAlert(object):
    """
    This is an object to generate properly APNS alert object with
    all possible values.
    """
    def __init__(self):
        self.alertBody = None
        self.actionLocKey = None
        self.locKey = None
        self.locArgs = None

    def body(self, alertBody):
        """
        The text of the alert message.
        """
        if alertBody and not isinstance(alertBody, basestring):
            raise APNSValueError("Unexpected value of argument. "
                                 "It should be string or None.")

        self.alertBody = alertBody
        return self

    def action_loc_key(self, alk=None):
        """
        If a string is specified, displays an alert with two buttons.
        """
        if alk and not isinstance(alk, basestring):
            raise APNSValueError("Unexpected value of argument. "
                                 "It should be string or None.")

        self.actionLocKey = alk
        return self

    def loc_key(self, lk):
        """
        A key to an alert-message string in a
        Localizable.strings file for the current
        localization (which is set by the user's language preference).
        """
        if lk and not isinstance(lk, basestring):
            raise APNSValueError("Unexpected value of argument. "
                                 "It should be string or None")
        self.locKey = lk
        return self

    def loc_args(self, la):
        """
        Variable string values to appear in place of
        the format specifiers in loc-key.
        """

        if la and not isinstance(la, (list, tuple)):
            raise APNSValueError("Unexpected type of argument. "
                                 "It should be list or tuple of strings")

        self.locArgs = [unicode(x) for x in la]
        return self

    def __json__(self):
        """
        Build object to JSON Apple Push Notification Service string.
        """

        attr_map = {
            u'body': 'alertBody',
            u'action-loc-key': 'actionLocKey',
            u'loc-key': 'locKey',
            u'loc-args': 'locArgs',
        }
        data = {}
        for k, a in attr_map.iteritems():
            v = getattr(self, a, None)
            if v:
                data[k] = v
        return data

    def __unicode__(self):
        return encode_json(self.__json__())

    def __str__(self):
        return unicode(self).encode('utf-8')


class APNSNotificationWrapper(object):
    """
    This object wrap a list of APNS tuples. You should use
    .append method to add notifications to the list. By usint
    method .notify() all notification will send to the APNS server.
    """
    sandbox = True
    apnsHost = 'gateway.push.apple.com'
    apnsSandboxHost = 'gateway.sandbox.push.apple.com'
    apnsPort = 2195
    payloads = None
    connection = None
    debug_ssl = False

    def __init__(self, certificate=None, sandbox=True, debug_ssl=False,
                 force_ssl_command=False):
        self.debug_ssl = debug_ssl
        self.connection = APNSConnection(certificate=certificate,
                                         force_ssl_command=force_ssl_command,
                                         debug=self.debug_ssl)
        self.sandbox = sandbox
        self.payloads = []

    def append(self, payload=None):
        """Append payload to wrapper"""
        if not isinstance(payload, APNSNotification):
            raise APNSTypeError("Unexpected argument type. Argument should "
                                "be an instance of APNSNotification object")
        self.payloads.append(payload)

    def count(self):
        """Get count of payloads
        """
        return len(self.payloads)

    def connect(self):
        """Make connection to APNS server"""

        apnsHost = self.apnsSandboxHost if self.sandbox else self.apnsHost
        self.connection.connect(apnsHost, self.apnsPort)

    def disconnect(self):
        """Close connection ton APNS server"""
        self.connection.close()

    def notify(self):
        """
        Send nofification to APNS:
            1) prepare all internal variables to APNS Payout JSON
            2) send notification
        """
        payloads = [o.payload() for o in self.payloads]
        if not payloads:
            return False

        messages = []
        for p in payloads:
            messages.append(struct.pack('%ds' % len(p), p))

        message = "".join(messages)
        self.connection.write(message)

        return True


class APNSNotification(object):
    """
    APNSNotificationWrapper wrap Apple Push Notification Service into
    python object.
    """

    command = 0
    badgeValue = None
    soundValue = None
    alertObject = None

    deviceToken = None

    maxPayloadLength = 256
    deviceTokenLength = 32

    properties = None

    def __init__(self):
        """
        Initialization of the APNSNotificationWrapper object.
        """
        self.properties = {}
        self.badgeValue = None
        self.soundValue = None
        self.alertObject = None
        self.deviceToken = None

    def token(self, token):
        """
        Add deviceToken in binary format.
        """
        self.deviceToken = token
        return self

    def tokenBase64(self, encodedToken):
        """
        Add deviceToken as base64 encoded string (not binary)
        """
        self.deviceToken = base64.standard_b64decode(encodedToken)
        return self

    def tokenHex(self, hexToken):
        """
        Add deviceToken as a hexToken
        Strips out whitespace and <>
        """
        hexToken = (hexToken
                    .strip()
                    .strip('<>')
                    .replace(' ', '')
                    .replace('-', ''))
        self.deviceToken = binascii.unhexlify(hexToken)

        return self

    def unbadge(self):
        """Simple shorcut to remove badge from your application.
        """
        self.badge(0)
        return self

    def badge(self, num=None):
        """
        Add badge to the notification. If argument is
        None (by default it is None)
        badge will be disabled.
        """
        if num is None:
            self.badgeValue = None
            return self

        if not isinstance(num, int):
            raise APNSValueError("Badge argument must be a number")
        self.badgeValue = num
        return self

    def sound(self, sound='default'):
        """
        Add a custom sound to the notification.
        By defailt it is default sound ('default')
        """
        if sound is None:
            self.soundValue = None
            return self
        self.soundValue = unicode(sound)
        return self

    def alert(self, alert=None):
        """
        Add an alert to the Wrapper. It should be string or
        APNSAlert object instance.
        """
        if not isinstance(alert, (basestring, APNSAlert)):
            raise APNSTypeError("Wrong type of alert argument. Argument "
                                "should be String, Unicode string or an "
                                "instance of APNSAlert object")
        self.alertObject = alert
        return self

    def setProperty(self, key, value):
        """
        Add a custom property to list of properties.
        """
        self.properties[key] = value
        return self

    def clearProperties(self):
        """
        Clear list of properties.
        """
        self.properties = {}

    def __json__(self):
        """
        Build all notifications items to one string.
        """
        data = {'aps': {}}
        data.update(self.properties)
        if self.soundValue:
            data['aps']['sound'] = self.soundValue

        if self.badgeValue:
            data['aps']['badge'] = self.badgeValue

        if self.alertObject:
            data['aps']['alert'] = self.alertObject

        return data

    def __unicode__(self):
        return encode_json(self.__json__())

    def __str__(self):
        return unicode(self).encode('utf-8')

    def payload(self):
        """Build payload via struct module"""
        if not self.deviceToken:
            raise APNSUndefinedDeviceToken("You forgot to set deviceToken "
                                           "in your notification.")

        payload = str(self)
        if len(payload) > self.maxPayloadLength:
            raise APNSPayloadLengthError("Length of Payload more than "
                                         "%d bytes." % self.maxPayloadLength)

        apnsPackFormat = "!BH{0}sH{1}s".format(len(self.deviceToken),
                                               len(payload))

        return struct.pack(apnsPackFormat,
                           self.command,
                           len(self.deviceToken),
                           self.deviceToken,
                           len(payload),
                           payload)
