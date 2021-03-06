import json
import os

import pytest

from mtls_custom_auth import app


@pytest.fixture()
def apigw_event():
    """ Loads API GW Event"""
    tests_root = os.path.dirname(__file__)
    with open(os.path.join(tests_root,'../../events_and_trust_store/event_dev_ocio_ca.json'), 'rb') as f:
        event = json.load(f)

    return event


def test_lambda_handler(apigw_event, mocker):

    ret = app.lambda_handler(apigw_event, "")
    print("Received ret: " + json.dumps(ret, indent=2))

    # Probably need to refactor, due to "EnableSimpleResponses: false"
    # TODO: Add example event with non-revoked cert, and verify resulting policy doc.
    assert "isAuthorized" in ret
    assert ret["isAuthorized"] == "true"
    assert ret["context"]["exception"] == None
