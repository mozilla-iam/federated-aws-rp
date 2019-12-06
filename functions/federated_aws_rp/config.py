import os
import urllib.parse

from jinja2 import Template


class Config:
    def __init__(self):
        self.client_id = os.getenv('CLIENT_ID')
        self.domain_name = os.getenv('DOMAIN_NAME')
        self.discovery_url = os.getenv('DISCOVERY_URL')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.id_token_for_roles_url = os.getenv('ID_TOKEN_FOR_ROLES_URL')

        self.bypass_cache = False
        self.default_session_duration = 43200  # 12 hours
        self.redirect_uri_path = '/redirect_uri'
        # self.oidc_scope = 'openid email'
        self.oidc_scope = 'openid'
        self.redirect_uri = urllib.parse.urlunparse(
            ('https', self.domain_name, self.redirect_uri_path, '', '', ''))
        self.cookie_name = 'federated-aws-rp'

        self.default_destionation_url = (
            'https://console.aws.amazon.com/console/home')
        self.role_picker_template = Template('''{% block body %}
  <ul>
  {% for role in roles %}
    <li><a href="/pick_role?role_arn={{ role.arn }}">{{ role.name }}</a><br><span style="margin-left: 2em;">Account: {{role.alias}} ({{role.id}})</span></li>
  {% endfor %}
  </ul>
{% endblock %}''')


CONFIG = Config()
