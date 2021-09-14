import json
import os
import requests

# define the api-endpoint 
apiEndpoint = os.environ.get('API_ENDPOINT')

# define the validation policy
vssPolicy = os.environ.get('VSS_POLICY')

def pem_to_vsscert(event):
    # strip PEM tags and newlines for out VSS request
    pem = event["requestContext"]["authentication"]["clientCert"]["clientCertPem"]
    pem = pem.replace("-----BEGIN CERTIFICATE-----","")
    pem = pem.replace("-----END CERTIFICATE-----","")
    return pem.replace("\n","")

def lambda_handler(event, context):
    evtJson = {"ReceivedEvent": event}
    print(json.dumps(evtJson))
    cert = pem_to_vsscert(event)
    # data to be sent to api
    data = {"validationPolicy":vssPolicy,
            "wantBackList":[],
            "x509CertificateList":[{
                "x509Certificate":cert
                }]
            }
    # sending post request and saving response as response object
    response = requests.post(url = apiEndpoint, json=data)
    # parse the VSS response
    resJson = response.json()
    # parse the individaul resultByCertificate
    certResult = resJson["validationResult"]["resultsByCertificateList"][0]
    validationResultToken = certResult["resultByCertificate"]["validationResultToken"]
    # parse subject from the VSS response to add as principalId to the response policy
    principalId = certResult["resultByCertificate"]["x509SubjectName"]
    # if the validationResultToken is "FAIL", then respond with access denial, and provide the VSS invalidityReasonText
    if validationResultToken == "FAIL":
        invalidityReasonText = certResult["resultByCertificate"]["validationFailureData"]["invalidityReasonList"][0]["invalidityReasonText"]
        errJson = {"validationResultToken": "FAIL", "vssResponse": resJson}
        print(json.dumps(errJson))
        return {
            "principalId": principalId,
            "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": "Deny",
                "Resource": "*"
            }
            ]},
            "context": {"exception":invalidityReasonText}
        } 
    # otherwise, grant access
    else:
        successJson = {"validationResultToken": "SUCCESS", "vssResponse": resJson}
        print(json.dumps(successJson))
        return {
            "principalId": principalId,
            "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
            {
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": "*"
            }
            ]},
            "context": {"exception":None}
        }
