import base64
import json
import logging
import urllib.parse
import http.cookies
from typing import Optional

from jose import jwt
import requests
import boto3

from .config import CONFIG

logger = logging.getLogger(__name__)


class AccessDenied(Exception):
    pass


def base64_without_padding(data: bytes) -> str:
    """Return the base64 encoding of data with padding stripped

    https://tools.ietf.org/html/rfc7636#appendix-A
    :param data: Bytes to encode
    :return: A base64 encoded string with padding stripped
    """
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def encode_cookie_value(value: dict) -> str:
    """Given a dictionary, JSON dump it and encode the result for a cookie

    :param value: A dictionary to encode
    :return: An encoded string to be set in a cookie
    """
    return http.cookies.SimpleCookie().value_encode(
        json.dumps(value, separators=(',', ':')))[1]


def get_store(cookie_header: str) -> dict:
    """Given an HTTP cookie header return the store

    Extract the cookie with the name CONFIG.cookie_name from the cookie_header
    parse the JSON from it and return it

    :param cookie_header: The content of the "Cookie" HTTP header
    :return: The value of the cookie
    """
    cookies = http.cookies.SimpleCookie()
    cookies.load(cookie_header)
    if CONFIG.cookie_name in cookies:
        try:
            return json.loads(cookies[CONFIG.cookie_name].value)
        except Exception:
            logger.error('Unable to parse  JSON from "{}"'.format(
                cookies[CONFIG.cookie_name].value
            ))
            return {}
    else:
        return {}


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


def exchange_code_for_token(
        code_verifier: str,
        token_endpoint: str,
        code: str) -> dict:
    """Request an OIDC token from the token endpoint using the code provided

    Submit the code and code_verifier to the token endpoint and return a token
    dictionary which contains the ID token

    :param dict code_verifier: The original code_verifier
    :param str token_endpoint: The URL of the token endpoint
    :param str code: A string returned from the identity provider
    :return: A dictionary containing the encoded ID token
    """
    headers = {
        "Content-Type": "application/json"
    }
    body = {
        "grant_type": "authorization_code",
        "client_id": CONFIG.client_id,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": CONFIG.redirect_uri,
    }

    # TODO : Wait should we not do PKCE because this is a traditional RP
    # and instead use a client secret?
    logger.debug('Requesting token with arguments {}'.format(body))
    return requests.post(
        token_endpoint,
        headers=headers,
        json=body).json()


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


def get_api_keys(
        jwks: str,
        id_token: str,
        role_arn: str,
        session_duration: int) -> dict:
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
        # role_arn is less than session_duration this will fail.
        logger.debug(
            'Calling assume_role_with_web_identity with role ARN {} session '
            'name {} and duration {}'.format(
                role_arn,
                role_session_name,
                session_duration
            ))
        response = client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
            WebIdentityToken=id_token,
            DurationSeconds=session_duration
        )
        return response['Credentials']
    except Exception as e:
        raise AccessDenied("Unable to fetch STS credentials : {}".format(e))


def get_signin_url(
        credentials: dict,
        issuer_url: str,
        destination_url: Optional[str]) -> str:
    """Exchange a set of AWS API keys for a web console sign in URL

    Call the getSigninToken API to exchange AWS API keys for a sign in token.
    Construct a sign in URL using the sign in token along with the issuer URL
    and the destination URL and return the resulting sign in URL
    :param credentials: A dictionary containing AWS API keys and session info
    :param issuer_url: The URL to redirect the user to when their session
        expires
    :param destination_url: The URL to redirect the user to once signin
        finishes
    :return: A URL
    """
    creds = {
        "sessionId": credentials["AccessKeyId"],
        "sessionKey": credentials["SecretAccessKey"],
        "sessionToken": credentials["SessionToken"],
    }
    if destination_url is None:
        destination_url = CONFIG.default_destionation_url

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
        "Destination": destination_url,
        "SigninToken": token["SigninToken"],
        "Issuer": issuer_url
    })
    url = urllib.parse.urlunparse(url_tuple._replace(query=query))
    logger.debug("Web browser console URL: {}".format(url))
    return url


def get_destination_url(referer: str) -> str:
    """Given a referer URL extract the redirect_uri and return it

    If the referer is an AWS signin referer, extract the redirect_uri query
    parameter, remove from the redirect_uri the state and isauthcode query
    parameters and return the modified redirect_uri. Otherwise return the
    default destination of CONFIG.default_destionation_url

    :param referer:
    :return:
    """
    referer_tuple = urllib.parse.urlparse(referer)
    if (not referer_tuple.netloc.endswith('.signin.aws.amazon.com')
            or not referer_tuple.path == '/oauth'):
        return CONFIG.default_destionation_url
    try:
        referer_query_params = urllib.parse.parse_qs(referer_tuple.query)
        if 'redirect_uri' not in referer_query_params:
            return CONFIG.default_destionation_url
        redirect_uri_tuple = urllib.parse.urlparse(
            referer_query_params['redirect_uri'][0])
        redirect_query_params = urllib.parse.parse_qsl(
            redirect_uri_tuple.query)
        dest_query_params = []
        for param_pair in redirect_query_params:
            if param_pair[0].lower() not in ('state', 'isauthcode'):
                dest_query_params.append(param_pair)
        return urllib.parse.urlunparse(redirect_uri_tuple._replace(
            query=urllib.parse.urlencode(dest_query_params)))
    except Exception as e:
        return CONFIG.default_destionation_url


def redirect_to_web_console(
        jwks: str,
        store: dict) -> dict:
    """Given an ID token and IAM Role return a AWS API Gateway redirect to AWS

    Use the ID token and IAM Role ARN to fetch temporary AWS API keys from STS
    then use those API Keys to get a sign in URL (containing a sign in token)
    and finally return an dictionary suitable for use by AWS API Gateway
    that instructs API Gateway to redirect the user to the sign in URL and pass
    any additional headers (like cookies) that are set in multi_value_headers

    :param jwks: The JSON Web Key Set for the identity provider
    :param store: The data store containing the role_arn, destination_url and
        id_token
    :return:
    """
    if 'role_arn' not in store:
        raise AccessDenied(
            'Missing "role_arn" query parameter')
    credentials = get_api_keys(
        jwks,
        store.get('id_token'),
        store['role_arn'],
        store['session_duration'])
    issuer_url_query = urllib.parse.urlencode({
        "role_arn": store['role_arn']
    })
    issuer_url = urllib.parse.urlunparse(
        ('https', CONFIG.domain_name, '/', '', issuer_url_query, ''))
    url = get_signin_url(credentials, issuer_url, store.get('destination_url'))
    # TODO : handle requests failures
    response = {
        'statusCode': 302,
        'headers': {
            'Content-Type': 'text/html',
            'Location': url,
            'Set-Cookie': '{}={}; Secure; HttpOnly; Max-Age=3600'.format(
                CONFIG.cookie_name,
                encode_cookie_value(store))
        },
        'body': 'Redirecting to AWS Web Console'
    }
    return response
