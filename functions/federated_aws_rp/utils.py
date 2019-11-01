import base64
import json
import logging
import time
import urllib.parse
import http.cookies
from typing import Optional

from jose import jwt
import requests
import boto3

from .config import CONFIG

logger = logging.getLogger(__name__)
STORE_KEYS = ('cookie', 'code_verifier', 'role_arn', 'expiry')


class AccessDenied(Exception):
    pass


def base64_without_padding(data: bytes) -> str:
    """Return the base64 encoding of data with padding stripped

    https://tools.ietf.org/html/rfc7636#appendix-A
    :param data: Bytes to encode
    :return: A base64 encoded string with padding stripped
    """
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def get_cookies(cookie_header: str, cookie_name: str) -> str:
    """Given an API Gateway proxy Lambda event, return a cookies object

    :param cookie_header: The content of the "Cookie" HTTP header
    :param cookie_name: The name of the cookie to fetch the value for
    :return: The value of the cookie
    """
    cookies = http.cookies.SimpleCookie()
    cookies.load(cookie_header)
    if cookie_name in cookies:
        return cookies[cookie_name].value
    else:
        return ''


def get_store() -> dict:
    """Fetch the store from S3

    :return: dict
    """
    client = boto3.client('s3')
    try:
        logger.debug('Fetching store from S3')
        response = client.get_object(
            Bucket=CONFIG.s3_bucket_name,
            Key=CONFIG.s3_file_path_store)
    except client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return dict()
        else:
            raise
    return json.load(response['Body'])


def put_store(store):
    """Serialize the store dictionary to json and write it to S3

    :param store: The dictionary to serialize
    :return:
    """
    # Cleanup expired data in the store
    states = list(store.get('expiry', {}).keys())
    for state in states:
        if store['expiry'][state] < time.time():
            for key in STORE_KEYS:
                if state in store.get(key):
                    logger.debug('Deleting {} {} because of expiry {}'.format(
                        key,
                        state,
                        store['expiry'][state]))
                    del store[key][state]
    # for key in STORE_KEYS:
    #     for state in list(store.get(key, {}).keys()):
    #         if state not in store['expiry'] and state in store[key]:
    #             del store[key][state]
    client = boto3.client('s3')
    logger.debug('Writing store to S3 with {} states'.format(
        len(store.get('expiry', {}))
    ))
    client.put_object(
        Body=json.dumps(store, sort_keys=True, indent=4).encode('utf-8'),
        Bucket=CONFIG.s3_bucket_name,
        Key=CONFIG.s3_file_path_store,
        ContentType='application/json'
    )
    return store


def get_discovery_document(discovery_url: str) -> dict:
    """Fetch the OIDC discovery document and enrich it with the JWKS

    Fetch the the discovery_url and parse it into a dictionary. Fetch the
    content of the jwks_uri and add it to the dictionary in the "jkws" key

    :param discovery_url: The URL of the identity providers OIDC discovery url
    :return: A dictionary containing information about the identity provider
    """
    result = requests.get(discovery_url).json()
    result['jwks'] = requests.get(result['jwks_uri']).json()
    return result


def check_state(store: dict, state: str, cookie_value: str):
    """Validate that the OIDC state and cookie are valid

    Check that the OIDC state exists in the store and that the user's cookie
    matches the cookie stored with the state in the store

    :param dict store: The data store containing the original cookie payload
    :param str state: A 32 character string
    :param str cookie_value: A 32 character string
    :return: The updated store
    """
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
    if 'cookie' not in store or state not in store['cookie']:
        raise AccessDenied('Invalid "state" query parameter passed')
    if not cookie_value:
        raise AccessDenied(
            'Missing cookie {}'.format(CONFIG.login_cookie_name))
    if store['cookie'][state] != cookie_value:
        logger.debug('Cookie mismatch : store {}, cookie {}'.format(
            store['cookie'][state],
            cookie_value
        ))
        raise AccessDenied(
            '"state" query parameter does not match {} cookie'.format(
                CONFIG.login_cookie_name))
    del store['cookie'][state]
    return store


def exchange_code_for_token(
        store: dict,
        token_endpoint: str,
        code: str,
        state: str) -> dict:
    """Request an OIDC token from the token endpoint using the code provided

    Fetch the code_verifier from the store that was generated earlier and
    stored with the state. Submit the code and code_verifier to the token
    endpoint and return an encoded ID token

    :param dict store: The data store containing the original code_verifier
    :param str token_endpoint: The URL of the token endpoint
    :param str code: A string returned from the identity provider
    :param str state: A 32 character string
    :return: A dictionary containing the encoded ID token
    """
    headers = {
        "Content-Type": "application/json"
    }
    body = {
        "grant_type": "authorization_code",
        "client_id": CONFIG.client_id,
        "code_verifier": store['code_verifier'][state],
        "code": code,
        "redirect_uri": CONFIG.redirect_uri,
    }

    # TODO : Wait should we not do PKCE because this is a traditional RP
    # and instead use a client secret?
    logger.debug('Requesting token with arguments {}'.format(body))
    token = requests.post(
        token_endpoint,
        headers=headers,
        json=body).json()
    return token


def exchange_token_for_roles(jwks: str, id_token: str) -> dict:
    """Call the id_token_for_roles endpoint exchanging a token for a roles

    POST an ID token to the id_token_for_roles API endpoint. The API will
    extract the list of groups that the user is a member of from the "amr"
    field of the ID token. It will then search through the IAM Roles it knows
    about to determine which roles allow those groups. It then returns a list
    of IAM roles and AWS account aliases

    :param jwks: The JSON Web Key Set for the identity provider
    :param id_token: A dictionary containing the encoded ID token
    :return: A dictionary containing roles and aliases
    """
    headers = {"Content-Type": "application/json"}
    body = {"token": id_token, "key": jwks}
    try:
        result = requests.post(
            CONFIG.id_token_for_roles_url, headers=headers, json=body)
        if result.status_code != requests.codes.ok or "error" in result.json():
            raise AccessDenied(
                '{} : {}'.format(result.status_code, result.text))
    except Exception as e:
        raise AccessDenied(
            "Unable to exchange ID token for list of roles : {}".format(e))
    return result.json()


def get_api_keys(jwks: str, id_token: str, role_arn: str) -> dict:
    """Exchange an ID token for a set of AWS STS API keys

    Submit an OIDC ID token to the STS AssumeRoleWithWebIdentity endpoint to
    request a set of temporary AWS API keys

    :param jwks: The JSON Web Key Set for the identity provider
    :param id_token: An encoded OIDC ID token
    :param role_arn: An AWS Amazon Resource Name (ARN) of an AWS IAM Role to
                     assume
    :return: A dictionary containing the AWS API keys and session information
    """
    try:
        id_token_dict = jwt.decode(
            token=id_token,
            key=jwks,
            audience=CONFIG.client_id)
    except Exception as e:
        raise AccessDenied("Unable to parse ID token : {}".format(e))
    role_session_name = (
        id_token_dict['email']
        if 'email' in id_token_dict
        else id_token_dict['sub'].split('|')[-1])

    # Call the STS API
    try:
        client = boto3.client('sts')
        # If the MaxSessionDuration configured on the role described by
        # role_arn is less than 43200 this will fail.
        response = client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
            WebIdentityToken=id_token,
            DurationSeconds=43200
        )
        return response['Credentials']
    except Exception as e:
        raise AccessDenied("Unable to fetch STS credentials : {}".format(e))


def get_signin_url(credentials: dict) -> str:
    """Exchange a set of AWS API keys for a web console sign in URL

    Call the getSigninToken API to exchange AWS API keys for a sign in token,
    then construct a sign in URL and return it
    :param credentials: A dictionary containing AWS API keys and session info
    :return: A URL
    """
    creds = {
        "sessionId": credentials["AccessKeyId"],
        "sessionKey": credentials["SecretAccessKey"],
        "sessionToken": credentials["SessionToken"],
    }

    query = urllib.parse.urlencode({
        "Action": "getSigninToken",
        "Session": json.dumps(creds),
    })

    logger.debug("Web Console query: {}".format(query))

    url_tuple = urllib.parse.urlparse(
        'https://signin.aws.amazon.com/federation')
    url = urllib.parse.urlunparse(url_tuple._replace(query=query))
    token = requests.get(url).json()

    query = urllib.parse.urlencode({
        "Action": "login",
        "Destination": "https://console.aws.amazon.com/",
        "SigninToken": token["SigninToken"],
    })
    url = urllib.parse.urlunparse(url_tuple._replace(query=query))
    logger.debug("Web browser console URL: {}".format(url))
    return url


def redirect_to_web_console(
        jwks: str,
        id_token: str,
        role_arn: str,
        multi_value_headers: Optional[dict] = None) -> dict:
    """Given an ID token and IAM Role return a AWS API Gateway redirect to AWS

    Use the ID token and IAM Role ARN to fetch temporary AWS API keys from STS
    then use those API Keys to get a sign in URL (containing a sign in token)
    and finally return an dictionary suitable for use by AWS API Gateway
    that instructs API Gateway to redirect the user to the sign in URL and pass
    any additional headers (like cookies) that are set in multi_value_headers

    :param jwks: The JSON Web Key Set for the identity provider
    :param id_token: An encoded OIDC ID token
    :param role_arn: An AWS Amazon Resource Name (ARN) of an AWS IAM Role to
        assume
    :param multi_value_headers: A dictionary of HTTP headers and their
        associated values suitable for consumption by AWS API Gateway
    :return:
    """
    if multi_value_headers is None:
        multi_value_headers = {}
    if role_arn is None:
        raise AccessDenied(
            'Missing "role" query parameter')
    credentials = get_api_keys(jwks, id_token, role_arn)
    url = get_signin_url(credentials)
    # TODO : handle requests failures
    multi_value_headers.update([('Location', [url])])
    response = {
        'statusCode': 302,
        'headers': {'Content-Type': 'text/html'},
        'multiValueHeaders': multi_value_headers,
        'body': 'Redirecting to AWS Web Console'
    }
    return response
