import json
import requests
  
# define the api-endpoint 
API_ENDPOINT = "https://vssapi-dev.treasury.gov/vss/rest/"

# define the validation policy
VSS_POLICY = "1.3.6.1.5.5.7.19.1"

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
    data = {"validationPolicy":VSS_POLICY,
            "wantBackList":[],
            "x509CertificateList":[{
                "x509Certificate":cert
                }]
            }
    # sending post request and saving response as response object
    response = requests.post(url = API_ENDPOINT, json=data)
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
