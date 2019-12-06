import os
import hashlib
import logging
import traceback
import urllib.parse
from typing import Optional

from jose import jwt

from .config import CONFIG
from .utils import (
    AccessDenied,
    base64_without_padding,
    get_store,
    get_discovery_document,
    get_destination_url,
    get_role_arn,
    encode_cookie_value,
    exchange_code_for_token,
    exchange_token_for_roles,
    redirect_to_web_console,
    trigger_group_role_map_rebuild
)

logger = logging.getLogger()
logging.getLogger().setLevel(CONFIG.log_level)
logging.getLogger('boto3').propagate = False
logging.getLogger('botocore').propagate = False
logging.getLogger('urllib3').propagate = False


# /pick_role
def pick_role(cookie_header: str, role_arn: str) -> dict:
    """API Gateway /pick_role endpoint which the user goes to when they've
    selected an AWS IAM Role from the role picker web page

    :param cookie_header: Content of the "Cookie" HTTP header
    :param role_arn: The AWS IAM Role ARN selected from the role picker
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    global discovery_document
    if 'discovery_document' not in globals():
        logger.debug('Fetching discovery document')
        discovery_document = get_discovery_document(CONFIG.discovery_url)

    store = get_store(cookie_header)
    store['role_arn'] = role_arn
    logger.debug('role_arn is {} of type {}'.format(role_arn, type(role_arn)))
    try:
        return redirect_to_web_console(
            discovery_document['jwks'],
            store)
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        return {
            'statusCode': 403,
            'headers': {'Content-Type': 'text/html'},
            'body': 'Access denied'}


# /redirect_uri
def login(state: str, code: str, cookie_header: str) -> dict:
    """API Gateway /redirect_uri endpoint which the user is redirected to after
    authenticating with the identity provider

    :param state: "state" query parameter returned by the identity provider
    :param code: "code" query parameter returned by the identity provider
    :param cookie_header: HTTP header cookies sent by the user
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    global discovery_document
    if 'discovery_document' not in globals():
        logger.debug('Fetching discovery document')
        discovery_document = get_discovery_document(CONFIG.discovery_url)

    try:
        if 'state' is None:
            raise AccessDenied('"state" query parameter is missing"')
        elif 'code' is None:
            raise AccessDenied('"code" query parameter is missing')
        store = get_store(cookie_header)
        if store.get('state') != state:
            raise AccessDenied('Invalid "state" query parameter passed')
        elif 'code_verifier' not in store:
            raise AccessDenied(
                '"code_verifier" not found in cookie')
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        return {
            'statusCode': 403,
            'headers': {'Content-Type': 'text/html'},
            'body': 'Access denied'}
    token = exchange_code_for_token(
        store['code_verifier'],
        discovery_document['token_endpoint'],
        code)
    jwt.decode(
        token=token['id_token'],
        key=discovery_document['jwks'],
        audience=CONFIG.client_id)
    store['id_token'] = token['id_token']
    return store


def login_to_web_console(store):
    global discovery_document
    if 'discovery_document' not in globals():
        logger.debug('Fetching discovery document')
        discovery_document = get_discovery_document(CONFIG.discovery_url)

    if 'role_arn' in store:
        return redirect_to_web_console(
            discovery_document['jwks'],
            store)
    else:
        # show role picker
        try:
            role_map = exchange_token_for_roles(
                discovery_document['jwks'],
                store['id_token'],
                store.get('cache', True))
        except AccessDenied as e:
            logger.error("Access denied : {}".format(e))
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'text/html'},
                'body': 'Access denied'}
        roles = {
            "roles": []
        }
        for arn in role_map["roles"]:
            account_id = arn.split(":")[4]
            alias = role_map.get(
                "aliases", {}).get(account_id, [account_id])[0]
            name = arn.split(':')[5].split('/')[-1]

            roles["roles"].append(
                {
                    "alias": alias,
                    "arn": arn,
                    "id": account_id,
                    "name": name,
                }
            )

        # Sort the list by role name
        roles["roles"] = sorted(roles["roles"], key=lambda x: x['name'])
        response = {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
                'Cache-Control': 'max-age=0',
                'Set-Cookie': '{}={}; Secure; HttpOnly; Max-Age=3600; SameSite=strict'.format(
                    CONFIG.cookie_name,
                    encode_cookie_value(store))
            },
            'body': CONFIG.role_picker_template.render(roles=roles["roles"])
        }
    return response


def group_role_map_rebuild(store):
    global discovery_document
    if 'discovery_document' not in globals():
        logger.debug('Fetching discovery document')
        discovery_document = get_discovery_document(CONFIG.discovery_url)
    try:
        result = trigger_group_role_map_rebuild(
            discovery_document['jwks'],
            store['id_token'])
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        return {
            'statusCode': 403,
            'headers': {'Content-Type': 'text/html'},
            'body': 'Access denied'}
    if 'error' in result:
        body = result['error']
    else:
        body = 'Success'
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html',
            'Cache-Control': 'max-age=0'
        },
        'body': body}


# /
def redirect_to_idp(
        action: str,
        destination_url: Optional[str] = None,
        role_arn: Optional[str] = None,
        session_duration: Optional[int] = None,
        cache: bool = True) -> dict:
    """API Gateway / endpoint which redirects the user to the identity
    provider

    :param action: What to do after authenticating to the identity provider
    :param destination_url: The URL to store in the cookie which will later
        be used to tell AWS what the "issuer URL" is that AWS should direct
        the user to when their session expires to have their session refreshed
    :param role_arn: An optional AWS IAM Role ARN
    :param session_duration: AN optional session duration in seconds
    :param cache: Whether or not to request a cached role list
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    global discovery_document
    if 'discovery_document' not in globals():
        # TODO : Am I doing this right with these globals?
        logger.debug('Fetching discovery document')
        discovery_document = get_discovery_document(CONFIG.discovery_url)

    code_verifier = base64_without_padding(os.urandom(32))
    code_challenge = base64_without_padding(hashlib.sha256(
        code_verifier.encode()).digest())
    state = base64_without_padding(os.urandom(32))
    store = {
        'action': action,
        'state': state,
        'code_verifier': code_verifier,
        'session_duration': session_duration,
        'cache': cache
    }
    if destination_url:
        store['destination_url'] = destination_url
    if role_arn:
        store['role_arn'] = role_arn

    url_parameters = {
        "scope": CONFIG.oidc_scope,
        "response_type": "code",
        "redirect_uri": CONFIG.redirect_uri,
        "client_id": CONFIG.client_id,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    # We don't set audience here because Auth0 will set the audience on
    # it's own
    auth_endpoint = urllib.parse.urlparse(
        discovery_document['authorization_endpoint'])
    redirect_url_tuple = auth_endpoint._replace(
        query=urllib.parse.urlencode(url_parameters))
    redirect_url = urllib.parse.urlunparse(redirect_url_tuple)
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-output-format
    response = {
        'statusCode': 302,
        'headers': {
            'Location': redirect_url,
            'Cache-Control': 'max-age=0',
            'Set-Cookie': '{}={}; Secure; HttpOnly; Max-Age=3600'.format(
                CONFIG.cookie_name,
                encode_cookie_value(store)),
            'Content-Type': 'text/html'
        },
        'body': 'Redirecting to identity provider'
    }
    return response


def lambda_handler(event: dict, context: dict) -> dict:
    """Handler for all API Gateway requests

    :param event: AWS API Gateway input fields for AWS Lambda
    :param context: Lambda context about the invokation and environment
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    global discovery_document

    path = event.get('path')
    logger.debug('event is {}'.format(event))
    headers = event['headers'] if event['headers'] is not None else {}
    cookie_header = headers.get('Cookie', '')
    referer = headers.get('Referer', '')
    query_string_parameters = (
        event['queryStringParameters']
        if event['queryStringParameters'] is not None else {})
    try:
        if path == '/':
            role_arn = get_role_arn(query_string_parameters)
            session_duration = int(query_string_parameters.get(
                'session_duration', CONFIG.default_session_duration))
            action = query_string_parameters.get(
                'action', 'aws-web-console')
            destination_url = get_destination_url(referer)
            cache = query_string_parameters.get(
                'cache', 'true').lower() == 'true'
            return redirect_to_idp(
                action,
                destination_url,
                role_arn,
                session_duration,
                cache)
        elif path == '/redirect_uri':
            state = query_string_parameters.get('state')
            code = query_string_parameters.get('code')
            store = login(state, code, cookie_header)
            logger.debug('Action is {}'.format(store.get('action')))
            if store.get('action') == 'aws-web-console':
                return login_to_web_console(store)
            elif store.get('action') == 'rebuild-group-role-map':
                return group_role_map_rebuild(store)
        elif path == '/pick_role':
            role_arn = query_string_parameters.get('role_arn')
            return pick_role(cookie_header, role_arn)
        else:
            logger.debug(
                'Path "{}" not found. Event is {}'.format(path, event))
            return {
                'headers': {'Content-Type': 'text/html'},
                'statusCode': 404,
                'body': 'Path not found'}
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        return {
            'headers': {'Content-Type': 'text/html'},
            'statusCode': 500,
            'body': 'Error'}
