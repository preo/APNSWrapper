#!/usr/bin/env python2.6
#
#  tests.py
#  wrapper
#
#  Created by max klymyshyn on 11/15/09.
#  Copyright (c) 2009 Sonettic. All rights reserved.
#

from APNSWrapper import (APNSNotification, APNSAlert, APNSNotificationWrapper,
                         APNSFeedbackWrapper)
import sys
import base64


def badge(wrapper, token):
    message = APNSNotification()
    message.tokenBase64(token)

    message.badge(3)
    print message
    wrapper.append(message)


def sound(wrapper, token):
    message = APNSNotification()
    message.tokenBase64(token)

    message.sound("default")
    print message
    wrapper.append(message)


def alert(wrapper, token):
    message = APNSNotification()
    message.tokenBase64(token)

    alert = APNSAlert()
    alert.body("Very important alert message")

    alert.loc_key("ALERTMSG")

    alert.loc_args(["arg1", "arg2"])
    alert.action_loc_key("OPEN")

    message.alert(alert)

    # properties wrapper
    message.setProperty("acme", (1, "custom string argument"))

    print message
    wrapper.append(message)


def testAPNSWrapper(encoded_token, cert_path='iphone_cert.pem', sandbox=True):
    cert_path = 'iphone_cert.pem'

    """
    Method to testing apns-wrapper module.
    """

    wrapper = APNSNotificationWrapper(cert_path,
                                      sandbox=sandbox,
                                      debug_ssl=True,
                                      force_ssl_command=False)
    badge(wrapper, encoded_token)
    sound(wrapper, encoded_token)
    alert(wrapper, encoded_token)
    wrapper.connect()
    wrapper.notify()
    wrapper.disconnect()

    feedback = APNSFeedbackWrapper(cert_path,
                                   sandbox=sandbox,
                                   debug_ssl=True,
                                   force_ssl_command=False)
    feedback.receive()

    print "\n".join(["> " + base64.standard_b64encode(y) for x, y in feedback])


if __name__ == "__main__":
    testAPNSWrapper(sys.argv[1])
