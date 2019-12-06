FEDERATED_AWS_RP_STACK_NAME	:= FederatedAWSRP
FEDERATED_AWS_RP_CODE_STORAGE_S3_PREFIX	:= federated-aws-rp
PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-east-1.iam.mozilla.com
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-east-1.security.allizom.org
PROD_ACCOUNT_ID		:= 320464205386
DEV_ACCOUNT_ID		:= 656532927350
PROD_DOMAIN_NAME	:= aws.sso.mozilla.com
DEV_DOMAIN_NAME		:= aws.security.allizom.org
PROD_DOMAIN_ZONE	:= sso.mozilla.com.
DEV_DOMAIN_ZONE		:= security.allizom.org.
PROD_CERT_ARN		:= arn:aws:acm:us-east-1:320464205386:certificate/29d28c00-40d2-4361-a6ef-f8b1441b171f
DEV_CERT_ARN		:= arn:aws:acm:us-east-1:656532927350:certificate/8f78c838-67e8-426b-8132-61165bf2cd7b
PROD_ID_TOKEN_FOR_ROLE_URL	:= https://roles-and-aliases.security.mozilla.org/
DEV_ID_TOKEN_FOR_ROLE_URL	:= https://roles-and-aliases.security.allizom.org/
PROD_CLIENT_ID		:= N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj
PROD_DISCOVERY_URL	:= https://auth.mozilla.auth0.com/.well-known/openid-configuration

.PHONE: deploy-aws-federated-rp-dev
deploy-aws-federated-rp-dev:
	./deploy.sh \
		 $(DEV_ACCOUNT_ID) \
		 federated-aws-rp.yaml \
		 $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(FEDERATED_AWS_RP_STACK_NAME) \
		 $(FEDERATED_AWS_RP_CODE_STORAGE_S3_PREFIX) \
		 "ClientId=$(PROD_CLIENT_ID) \
		 	DiscoveryUrl=$(PROD_DISCOVERY_URL) \
		 	CustomDomainName=$(DEV_DOMAIN_NAME) \
		 	DomainNameZone=$(DEV_DOMAIN_ZONE) \
		 	CertificateArn=$(DEV_CERT_ARN) \
		 	IdTokenForRolesUrl=$(DEV_ID_TOKEN_FOR_ROLE_URL)" \
		 AwsFederatedRpUrl

.PHONE: deploy-aws-federated-rp
deploy-aws-federated-rp:
	./deploy.sh \
		 $(PROD_ACCOUNT_ID) \
		 federated-aws-rp.yaml \
		 $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(FEDERATED_AWS_RP_STACK_NAME) \
		 $(FEDERATED_AWS_RP_CODE_STORAGE_S3_PREFIX) \
		 "ClientId=$(PROD_CLIENT_ID) \
		 	DiscoveryUrl=$(PROD_DISCOVERY_URL) \
		 	CustomDomainName=$(PROD_DOMAIN_NAME) \
		 	DomainNameZone=$(PROD_DOMAIN_ZONE) \
		 	CertificateArn=$(PROD_CERT_ARN) \
			IdTokenForRolesUrl=$(PROD_ID_TOKEN_FOR_ROLE_URL)" \
		 AwsFederatedRpUrl

.PHONE: test-aws-federated-rp
test-aws-federated-rp:
	URL=`aws cloudformation describe-stacks --stack-name $(FEDERATED_AWS_RP_STACK_NAME) --query "Stacks[0].Outputs[?OutputKey=='AliasesEndpointUrl'].OutputValue" --output text` && \
	curl $$URL

# TODO : Deal with the fact that this API isn't "deployed" when you first create the CloudFormation stack
# options : https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-deployment.html
# https://docs.aws.amazon.com/cli/latest/reference/apigateway/create-deployment.html
# web UI
# http://www.awslessons.com/2017/aws-api-gateway-missing-authentication-token/
