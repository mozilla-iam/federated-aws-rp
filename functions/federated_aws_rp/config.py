import os
import urllib.parse

from jinja2 import Template


class Config:
    pass


CONFIG = Config()
CONFIG.s3_bucket_name = os.getenv('S3_BUCKET_NAME')
CONFIG.s3_file_path_store = os.getenv(
    'S3_FILE_PATH_STORE', 'federated-aws-rp-store.json')
CONFIG.client_id = os.getenv('CLIENT_ID')
CONFIG.domain_name = os.getenv('DOMAIN_NAME')
CONFIG.discovery_url = os.getenv('DISCOVERY_URL')

CONFIG.bypass_cache = False
CONFIG.redirect_uri_path = '/redirect_uri'
# CONFIG.oidc_scope = 'openid email'
CONFIG.oidc_scope = 'openid'
CONFIG.redirect_uri = urllib.parse.urlunparse(
    ('https', CONFIG.domain_name, CONFIG.redirect_uri_path, '', '', ''))
CONFIG.login_cookie_name = 'federated-aws-rp'
CONFIG.token_cookie_name = 'federated-aws-rp-token'
CONFIG.id_token_for_roles_url = 'https://roles-and-aliases.security.mozilla.org/roles'
CONFIG.role_picker_template = Template('''{% block body %}
  <ul>
  {% for role in roles %}
    <li><a href="/pick_role?role={{ role.arn }}">{{ role.name }}</a><br><span style="margin-left: 2em;">Account: {{role.alias}} ({{role.id}})</span></li>
  {% endfor %}
  </ul>
{% endblock %}''')
