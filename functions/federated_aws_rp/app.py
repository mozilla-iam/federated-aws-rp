import base64
import hashlib
import json
import logging
import os
import time
import traceback
import urllib.parse
from typing import Optional

from .config import CONFIG
from .utils import (
    AccessDenied,
    base64_without_padding,
    convert_account_alias,
    encode_cookie_value,
    get_aws_federation_url,
    get_destination_url,
    get_discovery_document,
    get_role_arn,
    get_roles,
    get_store,
    login,
    read_resource,
    return_api_gateway_json,
    trigger_group_role_map_rebuild,
)

logger = logging.getLogger()
logging.getLogger().setLevel(CONFIG.log_level)
formatter = logging.Formatter(
    '%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] '
    '%(message)s',
    '%Y-%m-%d:%H:%M:%S')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logging.getLogger('boto3').propagate = False
logging.getLogger('botocore').propagate = False
logging.getLogger('urllib3').propagate = False


# POST /api/roles
def pick_role(store: dict) -> dict:
    """Exchange a role_arn for a AWS federation URL

    Get an AWS federation URL and store it in the client_workflow_value key of
    the cookie store

    :param store: The cookie store
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    discovery_document = get_discovery_document()
    try:
        aws_federation_url = get_aws_federation_url(
            discovery_document['jwks'],
            store)
        store['client_workflow_state'] = 'aws_federate'
        store['client_workflow_value'] = {
            'awsFederationUrl': aws_federation_url}
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        store['client_workflow_state'] = 'error'
        store['client_workflow_value'] = 'Access denied'

    return return_api_gateway_json(store)


# /redirect_callback
def handle_oidc_redirect_callback(cookie_header: str, body: dict) -> dict:
    """Get and ID token and store it in a cookie

    Exchange an OIDC code with the identity provider for an ID token.

    If the "action" query parameter was unset or set to aws-web-console :
        If the role_arn was passed as a query parameter in the initial call to
        the federated RP, then continue on and log the user in using that role.

        Otherwise, set the client_workflow_state to role_picker so the frontend
        displays the role picker

    If the initial "action" query parameter indicated to trigger a group role
    map rebuild, do so.

    :param cookie_header: String of the cookie HTTP header
    :param body: dictionary of query parameters returned in the redirect from
        the identity provider
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    discovery_document = get_discovery_document()
    store = get_store(cookie_header)
    try:
        logger.debug('/redirect_callback called with body {}'.format(body))
        store['id_token'] = login(
            body.get('state'),
            body.get('code'),
            body.get('error'),
            body.get('error_description'),
            cookie_header
        )
    except AccessDenied as e:
        logger.error("Access denied : {}".format(e))
        store['client_workflow_state'] = 'error'
        store['client_workflow_value'] = 'Access denied'
        return return_api_gateway_json(store)

    logger.debug('Action is {}'.format(store.get('action')))
    if store.get('action') == 'aws-web-console':
        if 'role_arn' in store:
            store['role_arn'] = convert_account_alias(
                store['role_arn'], store['id_token'], store.get('cache', True))
            return pick_role(store)
        else:
            # no role_arn passed, show role picker
            store['client_workflow_state'] = 'role_picker'
    elif store.get('action') == 'rebuild-group-role-map':
        # This is how we output a message, even though it's not an error
        store['client_workflow_state'] = 'error'
        try:
            result = trigger_group_role_map_rebuild(
                discovery_document['jwks'],
                store['id_token'])
            # TODO : do something with result
        except AccessDenied as e:
            logger.error("Access denied : {}".format(e))
            store['client_workflow_value'] = 'Access denied'
        else:
            store['client_workflow_value'] = 'Group Role Map rebuild initiated'
    else:
        logger.error('Invalid action argument {}'.format(store.get('action')))
        store['client_workflow_state'] = 'error'
        store['client_workflow_value'] = 'Invalid action argument'

    return return_api_gateway_json(store)


# GET /api/state
def get_state(store: dict) -> dict:
    """Fetch the current client_workflow_state from the user's cookie and
    return it

    Pull the client_workflow_state value from the users cookie store and return
    it to the frontend as the 'state' field

    :param store: The contents of the cookie store
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    # Update the last time state was checked
    store['last_state_check'] = time.time()
    return return_api_gateway_json(
        store,
        {
            'state': store.get('client_workflow_state'),
            'value': store.get('client_workflow_value')
        },
        False
    )


# /
def redirect_to_idp(
        action: str,
        destination_url: Optional[str] = None,
        role_arn: Optional[str] = None,
        session_duration: Optional[int] = None,
        cache: bool = True) -> dict:
    """API Gateway / endpoint which redirects the user to the identity
    provider

    Generate a code_verifier and associated code_challenge. Generate an OIDC
    state value. Store the code_verifier and statein the user's cookie store.

    Optionally also store a destination_url to have AWS send the user to upon
    session expiration.

    Construct a redirect URL with the code_challenge and OIDC state.

    Return the user a 302 redirect response to send them to the identity
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
    discovery_document = get_discovery_document()
    code_verifier = base64_without_padding(os.urandom(32))
    code_challenge = base64_without_padding(hashlib.sha256(
        code_verifier.encode()).digest())
    # We're using "1" as the prefixed number as the functionality that this
    # value provides in mozilla-aws-cli isn't needed in federated-aws-rp
    state = '1-{}'.format(base64_without_padding(os.urandom(32)))
    store = {
        'action': action,
        'oidc_state': state,
        'code_verifier': code_verifier,
        'session_duration': session_duration,
        'cache': cache,
        'client_workflow_state': None,
        'client_workflow_value': None
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
    logger.debug(
        'Redirecting the user to {} after setting the cookie store to '
        '{}'.format(redirect_url, store))
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-output-format
    response = {
        'statusCode': 302,
        'headers': {
            'Location': redirect_url,
            'Content-Type': 'text/html',
            'Cache-Control': 'max-age=0',
            'Set-Cookie': (
                '{}={}; Secure; HttpOnly; Path=/; Max-Age=3600'.format(
                    CONFIG.cookie_name,
                    encode_cookie_value(store)))
        },
        'body': 'Redirecting to identity provider'
    }
    return response


def lambda_handler(event: dict, context: dict) -> dict:
    """Handler for all API Gateway requests

    Based on the HTTP method and the URL path call the appropriate function

    :param event: AWS API Gateway input fields for AWS Lambda
    :param context: Lambda context about the invokation and environment
    :return: An AWS API Gateway output dictionary for proxy mode
    """
    # logger.debug('event is {}'.format(event))
    path = event.get('path')
    headers = event['headers'] if event['headers'] is not None else {}
    cookie_header = headers.get('Cookie', '')
    store = get_store(cookie_header)
    referer = headers.get('Referer', '')
    method = event.get('httpMethod')
    query_string_parameters = (
        event['queryStringParameters']
        if event['queryStringParameters'] is not None else {})
    logger.debug('{} "{}" and client_workflow_state read : {}'.format(
        method, path, store.get('client_workflow_state')))
    try:
        decoded_body = base64.b64decode(event.get('body', ''))
        parsed_body = json.loads(decoded_body)
    except (json.JSONDecodeError, TypeError) as e:
        parsed_body = {
            "error": "Unable to parse POST data",
            "body": event.get('body'),
            "exception": str(e)}
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
            store['client_workflow_state'] = 'redirecting'
            body = read_resource('/index.html')

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                    'Set-Cookie': (
                        '{}={}; Secure; HttpOnly; Path=/; Max-Age=3600; '
                        'SameSite=strict'.format(
                            CONFIG.cookie_name,
                            encode_cookie_value(store)))
                },
                'body': body
            }
        elif path == '/redirect_callback' and method == 'POST':
            return handle_oidc_redirect_callback(cookie_header, parsed_body)
        elif path == '/api/roles':
            if method == 'GET':
                roles = get_roles(store['id_token'], store.get('cache', True))
                store['client_workflow_state'] = 'awaiting_role'
                return return_api_gateway_json(store, roles)
            elif method == 'POST':
                if 'error' in parsed_body or 'arn' not in parsed_body:
                    logger.error(
                        'Invalid data POSTed to /api/roles : {}'.format(
                            parsed_body))
                    return {
                        'headers': {'Content-Type': 'text/html'},
                        'statusCode': 403,
                        'body': 'Invalid POST data'}

                store['role_arn'] = parsed_body['arn']
                return pick_role(store)
            else:
                return {
                    'headers': {'Content-Type': 'text/html'},
                    'statusCode': 405,
                    'body': 'Method not allowed'}
        elif path == '/api/state':
            return get_state(store)
        elif path == '/api/heartbeat':
            # As we have no need for a heartbeat, we'll just respond indicating
            # that it's running for ever
            return return_api_gateway_json(store, {'result': 'running'})
        elif path == '/shutdown':
            store['client_workflow_state'] = 'finished'
            return return_api_gateway_json(store)
        else:
            body = read_resource(path)
            if body:
                # static resource
                content_type_map = {
                    '.js': 'application/javascript',
                    '.html': 'text/html',
                    '.css': 'text/css',
                    '.woff': 'application/octet-stream',
                    '.woff2': 'application/octet-stream'
                }
                content_type = 'text/html'
                for extension in content_type_map:
                    if path.endswith(extension):
                        content_type = content_type_map[extension]
                is_base64_encoded = type(body) == bytes
                return {
                    'headers': {'Content-Type': content_type},
                    'statusCode': 200,
                    'isBase64Encoded': is_base64_encoded,
                    'body': (base64.b64encode(body) if is_base64_encoded
                             else body)}
            else:
                # 404
                logger.debug(
                    'Path "{}" not found.'.format(path))
                return {
                    'headers': {'Content-Type': 'text/html'},
                    'statusCode': 404,
                    'body': 'Not Found'}
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        return {
            'headers': {'Content-Type': 'text/html'},
            'statusCode': 500,
            'body': 'Error'}
