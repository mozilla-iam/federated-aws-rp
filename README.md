# Federated AWS RP

Federated AWS RP is an AWS API Gateway and Lambda OpenID Connect (OIDC) Relying 
Party (RP) to allow users to log into the AWS Management Console with their federated
identity using Single Sign On. This does not use [AWS SSO](https://aws.amazon.com/single-sign-on/)
which only works with Active Directory or SAML identity providers, and instead
uses [AWS identity providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html)
with OIDC.

Federated AWS RP is the sister project to [Mozilla AWS CLI](https://github.com/mozilla-iam/mozilla-aws-cli).
Federated AWS RP enables login to the AWS Management Console, where Mozilla AWS CLI
enables command line and API access to AWS.

The Federated AWS RP is a serverless service hosted via AWS API Gateway backed
by AWS Lambda. The backend API is designed to interact with the frontend in the
exact same way as the backend for the [Mozilla AWS CLI](https://github.com/mozilla-iam/mozilla-aws-cli)
so that both tools use the same frontend code and have the same UI.

* AWS Federated Login Website frontend code : https://github.com/mozilla-iam/federated-aws-rp/tree/master/functions/federated_aws_rp/static
* Mozilla AWS CLI frontend code : https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/mozilla_aws_cli/static

The Federated AWS RP website

* authenticates the user using SSO
* using the ID token received during SSO, fetches a list of AWS IAM Roles the user can assume
* presents an IAM Role picker to the user
* authenticates to AWS using the ID Token, assuming the selected IAM Role
* redirects the user to the AWS Management Console, now authenticated as the selected IAM Role

The Federated AWS RP depends on
* The [Group Role Map Builder](https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/cloudformation)
  being deployed
* The [ID Token for Roles API](https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/cloudformation)
  being deployed
* Being deployed in the `us-east-1` region as [that's the only region that supports
  https on the `/` endpoint](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html#https-requirements-aws-region)
* A pre-existing Route53 DNS name to use for the site and an associated pre-existing
  ACM certificate
* The identity provider passing the user's groups in the `amr` field of the ID
  Token. At Mozilla, we filter users' group lists passed in the `amr` field to
  workaround a limit in the size of the ID token passed to AWS using [a custom
  Auth0 rule](https://github.com/mozilla-iam/auth0-deploy/blob/master/rules/AWS-Federated-AMR.js)

More information can be found in the [Mozilla AWS CLI README](https://github.com/mozilla-iam/mozilla-aws-cli/blob/master/README.md).

At Mozilla this service is hosted at https://aws.sso.mozilla.com/ . More internal
Mozilla information can be found [in our internal documentation](https://mana.mozilla.org/wiki/display/SECURITY/AWS+Federated+Login+with+Single+Sign+On).

# Deploying

Run `make deploy-aws-federated-rp` to package up the [functions](https://github.com/mozilla-iam/federated-aws-rp/tree/master/functions/federated_aws_rp)
and the [CloudFormation template](https://github.com/mozilla-iam/federated-aws-rp/blob/master/federated-aws-rp.yaml)
and deploy the stack into AWS using CloudFormation

# Mozilla's Deployment

The dev instance of the Federated AWS RP is deployed in the `infosec-dev` AWS
account in `us-east-1` in the `FederatedAWSRP` CloudFormation stack and can
be accessed at https://aws.security.allizom.org/ . This dev instance talks to
the production Auth0 identity provider

The prod instance is deployed in the `mozilla-iam` AWS account in `us-east-1` in
the `FederatedAWSRP` CloudFormation stack and can be accessed at https://aws.sso.mozilla.com/