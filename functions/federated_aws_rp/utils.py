import base64
import http.cookies
import importlib.resources
import json
import logging
import urllib.parse
from typing import Optional

import boto3
import requests
from jose import jwt

from .config import CONFIG

logger = logging.getLogger(__name__)
logger.setLevel(CONFIG.log_level)


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
        except json.JSONDecodeError:
            logger.error('Unable to parse  JSON from "{}"'.format(
                cookies[CONFIG.cookie_name].value
            ))
            return {}
    else:
        return {}


def get_discovery_document() -> dict:
    """Fetch the OIDC discovery document and enrich it with the JWKS

    If the discovery_document is not available in AWS Lambda cache, fetch the
    CONFIG.discovery_url and parse it into a dictionary. Fetch the content of
    the jwks_uri and add it to the dictionary in the "jkws" key

    :return: A dictionary containing information about the identity provider
    """
    global discovery_document
    if 'discovery_document' not in globals():
        logger.debug('Fetching discovery document')
        discovery_document = requests.get(CONFIG.discovery_url).json()
        discovery_document['jwks'] = requests.get(
            discovery_document['jwks_uri']).json()
    return discovery_document


def get_role_arn(query_string_parameters: dict) -> Optional[str]:
    """Given a set of query parameters, return an IAM Role ARN

    :param query_string_parameters: Dictionary of URL query parameters
    :return: IAM Role ARN
    """
    if 'role_arn' in query_string_parameters:
        return query_string_parameters['role_arn']
    elif {'role', 'account'} <= query_string_parameters.keys():
        return 'arn:aws:iam::{}:role/{}'.format(
            query_string_parameters['account'],
            query_string_parameters['role'])
    else:
        return None


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


def exchange_token_for_roles(
        jwks: str, id_token: str, cache: bool = True) -> dict:
    """Call the id_token_for_roles endpoint exchanging a token for a roles

    POST an ID token to the id_token_for_roles API endpoint. The API will
    extract the list of groups that the user is a member of from the "amr"
    field of the ID token. It will then search through the IAM Roles it knows
    about to determine which roles allow those groups. It then returns a list
    of IAM roles and AWS account aliases

    :param jwks: The JSON Web Key Set for the identity provider
    :param id_token: A dictionary containing the encoded ID token
    :param cache: Whether or not to request a cached role list
    :return: A dictionary containing roles and aliases
    """
    headers = {"Content-Type": "application/json"}
    body = {"token": id_token, "key": jwks, "cache": cache}
    url = "{}roles".format(CONFIG.id_token_for_roles_url)
    try:
        result = requests.post(
            url, headers=headers, json=body)
        if (result.status_code != requests.codes.ok
                or "error" in result.json()
                or "roles" not in result.json()):
            raise AccessDenied(
                '{} : {}'.format(result.status_code, result.text))
    except Exception as e:
        raise AccessDenied(
            "Unable to exchange ID token for list of roles calling {} with "
            "payload {} : {}".format(url, body, e))
    return result.json()


def trigger_group_role_map_rebuild(jwks: str, id_token: str) -> dict:
    """Initiate a rebuild of the group role map

    Call the "rebuild-group-role-map" API endpoint for the id_token_for_role
    API which triggers scanning AWS accounts for IAM roles and producing an
    updated user group to IAM Role map

    :param jwks: The JSON Web Key Set for the identity provider
    :param id_token: A dictionary containing the encoded ID token
    :return: A dictionary indicating the result of the request
    """
    headers = {"Content-Type": "application/json"}
    body = {"token": id_token, "key": jwks}
    url = "{}rebuild-group-role-map".format(CONFIG.id_token_for_roles_url)
    logger.debug('POSTing {} to {} with headers {}'.format(body, url, headers))
    try:
        result = requests.post(
            url, headers=headers, json=body)
        logger.debug('POSTed {} to {} with headers {}'.format(
            body, url, result.request.headers))
        result.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise AccessDenied(
            '{} : {}'.format(
                getattr(e.response, 'status_code', None),
                getattr(e.response, 'text', None)
            ))

    if 'error' in result.json():
        raise AccessDenied(result.json()['error'])

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
    :param session_duration: AN optional session duration in seconds
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


def get_aws_federation_url(
        jwks: str,
        store: dict) -> str:
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
        "account": store['role_account_alias'],
        "role": store['role_name']
    })
    issuer_url = urllib.parse.urlunparse(
        ('https', CONFIG.domain_name, '/', '', issuer_url_query, ''))
    url = get_signin_url(credentials, issuer_url, store.get('destination_url'))
    # TODO : handle requests failures
    return url


def login(
        oidc_state: str,
        code: str,
        error: Optional[str],
        error_description: Optional[str],
        cookie_header: str) -> str:
    """Given an oidc_state and code, exchange them for an OIDC ID token

    Validate the oidc_state matches the oidc_state stored in the cookie store.
    Call exchange_code_for_token to get an ID token. Add the id_token to the
    store and return the store

    :param oidc_state: OIDC state value returned from the IdP
    :param code: OIDC code returned from the IdP
    :param error: Error code returned from the IdP
    :param error_description: Error description returned from the IdP
    :param cookie_header: HTTP header cookies sent by the user
    :return: An ID token
    """
    discovery_document = get_discovery_document()
    if error is not None:
        raise AccessDenied('Identity provider returned error : {}'.format(
            error_description))
    elif oidc_state is None:
        raise AccessDenied('"state" query parameter is missing"')
    elif code is None:
        raise AccessDenied('"code" query parameter is missing')

    store = get_store(cookie_header)
    if store.get('oidc_state') != oidc_state:
        raise AccessDenied('Invalid "state" query parameter passed')
    elif 'code_verifier' not in store:
        raise AccessDenied(
            '"code_verifier" not found in cookie')

    # TODO : wrap in try except, raise AccessDenied if there's a problem
    token = exchange_code_for_token(
        store['code_verifier'],
        discovery_document['token_endpoint'],
        code)
    if 'id_token' not in token:
        raise AccessDenied('Bad response from token endpoint : {}'.format(
            token))
    jwt.decode(
        token=token['id_token'],
        key=discovery_document['jwks'],
        audience=CONFIG.client_id)

    return token['id_token']


def get_roles(id_token: str, cache: bool) -> dict:
    """Fetch the role_map using an ID token and return it grouped and sorted

    :param id_token: The OIDC ID token
    :param cache: Whether or not to request a cached group role map
    :return: dictionary of the Group Role Map
    """
    discovery_document = get_discovery_document()
    try:
        role_map = exchange_token_for_roles(
            discovery_document['jwks'],
            id_token,
            cache)
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        return {}
    roles = {}  # type: dict
    for arn in role_map["roles"]:
        account_id = arn.split(":")[4]
        alias = role_map.get(
            "aliases", {}).get(account_id, [account_id])[0]
        name = arn.split(':')[5].split('/')[-1]
        role = {
            "alias": alias,
            "arn": arn,
            "id": account_id,
            "role": name
        }

        if alias in roles:
            roles[alias].append(role)
        else:
            roles[alias] = [role]

    # Sort the list by role name
    for alias in roles:
        roles[alias] = sorted(roles[alias], key=lambda x: x['role'])

    return roles


def convert_account_alias(
        role_arn: str,
        id_token: str,
        cache: bool) -> Optional[str]:
    """Given a role_arn with an AWS account alias in place of the account ID
    convert the alias to an account ID and return the modified role ARN

    :param role_arn: String of a AWS IAM Role ARN with an alias in place of
        the account ID
    :param id_token: String of OIDC ID token
    :param cache: Boolean of whether or not to use cached values
    :return: String of an AWS IAM Role ARN or None
    """
    if len(role_arn.split(':')) != 6:
        logger.error('Invalid role_arn : {}'.format(role_arn))
        return None
    role_arn_elements = role_arn.split(':')
    alias = role_arn_elements[4]
    if alias.isdigit() and len(alias) == 12:
        logger.debug(
            'role_arn does not require an alias lookup as {} is an account ID '
            'not an alias'.format(alias))
        return role_arn
    discovery_document = get_discovery_document()
    try:
        role_map = exchange_token_for_roles(
            discovery_document['jwks'],
            id_token,
            cache)
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        return None
    for account_id in role_map.get('aliases', {}):
        if alias in role_map['aliases'][account_id]:
            role_arn_elements[4] = account_id
            return ':'.join(role_arn_elements)
    logger.error('No AWS account found for alias "{}"'.format(alias))
    return None


def read_resource(
        path: str,
        prefix: str = 'federated_aws_rp/static') -> Optional[str]:
    """Read a file from the filesystem and return it

    :param path: The filename of the file
    :param prefix: The directory prefix of the file
    :return: The content of the on disk file
    """
    binary_extensions = ['woff', 'woff2']
    package = '.'.join((prefix + path).split('/')[:-1])
    name = '.'.join((prefix + path).split('/')[-1:])
    is_binary = any([name.endswith(x) for x in binary_extensions])
    # logger.debug('Reading resource package {} name {}'.format(package, name))
    try:
        if importlib.resources.is_resource(package, name):
            read_func = (importlib.resources.read_binary if is_binary
                         else importlib.resources.read_text)
            return read_func(package, name)
        else:
            return None
    except (ModuleNotFoundError, FileNotFoundError):
        return None


def return_api_gateway_json(
        store: Optional[dict],
        body: dict = None):
    """Return an AWS API Gateway AWS_PROXY JSON response

    Given a cookie store and a dictionary payload body, construct a valid
    response dictionary for AWS API Gateway.

    :param store: dictionary of the user's cookie store
    :param body: dictionary to be returned as JSON
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    if body is None:
        body = {}
    result = {
        'statusCode': 200,
        'multiValueHeaders': {
            'Content-Type': ['application/json'],
            'Cache-Control': ['max-age=0']
        },
        'body': json.dumps(body)
    }
    if store is not None:
        result['multiValueHeaders']['Set-Cookie'] = [
            '{}={}; Secure; HttpOnly; Path=/; Max-Age=3600; '
            'SameSite=strict'.format(
                CONFIG.cookie_name,
                encode_cookie_value(store))]
    return result
