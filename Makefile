FEDERATED_AWS_RP_STACK_NAME	:= FederatedAWSRP
FEDERATED_AWS_RP_CODE_STORAGE_S3_PREFIX	:= federated-aws-rp
PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.infosec.mozilla.org
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.allizom.org
PROD_ACCOUNT_ID		:= 371522382791
DEV_ACCOUNT_ID		:= 656532927350
PROD_RP_DATA_STORE_S3_BUCKET_NAME	:= prod-mozilla-aws-federated-rp-data-store
DEV_RP_DATA_STORE_S3_BUCKET_NAME	:= dev-mozilla-aws-federated-rp-data-store
PROD_DOMAIN_NAME	:= aws.security.mozilla.org
DEV_DOMAIN_NAME		:= aws.security.allizom.org
PROD_DOMAIN_ZONE	:= security.mozilla.org.
DEV_DOMAIN_ZONE		:= security.allizom.org.
PROD_CERT_ARN		:= arn:aws:acm:us-west-2:371522382791:certificate/697a9eb0-0145-4d18-ba7b-7d3b19c4eeed
DEV_CERT_ARN		:= arn:aws:acm:us-west-2:656532927350:certificate/46428d8b-7b26-4ad0-84d1-cd2d386e7a43
PROD_CLIENT_ID		:= N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj
# DEV_CLIENT_ID		:= xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT
PROD_DISCOVERY_URL	:= https://auth.mozilla.auth0.com/.well-known/openid-configuration
# DEV_DISCOVERY_URL	:= https://auth-dev.mozilla.auth0.com/.well-known/openid-configuration

.PHONE: deploy-aws-federated-rp-dev
deploy-aws-federated-rp-dev:
	./deploy.sh \
		 $(DEV_ACCOUNT_ID) \
		 federated-aws-rp.yaml \
		 $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(FEDERATED_AWS_RP_STACK_NAME) \
		 $(FEDERATED_AWS_RP_CODE_STORAGE_S3_PREFIX) \
		 "S3BucketName=$(DEV_RP_DATA_STORE_S3_BUCKET_NAME) \
		 	ClientId=$(PROD_CLIENT_ID) \
		 	DiscoveryUrl=$(PROD_DISCOVERY_URL) \
		 	CustomDomainName=$(DEV_DOMAIN_NAME) \
		 	DomainNameZone=$(DEV_DOMAIN_ZONE) \
		 	CertificateArn=$(DEV_CERT_ARN)" \
		 AwsFederatedRpUrl

.PHONE: deploy-aws-federated-rp
deploy-aws-federated-rp:
	./deploy.sh \
		 $(PROD_ACCOUNT_ID) \
		 federated-aws-rp.yaml \
		 $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(FEDERATED_AWS_RP_STACK_NAME) \
		 $(FEDERATED_AWS_RP_CODE_STORAGE_S3_PREFIX) \
		 "S3BucketName=$(PROD_RP_DATA_STORE_S3_BUCKET_NAME) \
		 	ClientId=$(PROD_CLIENT_ID) \
		 	DiscoveryUrl=$(PROD_DISCOVERY_URL) \
		 	CustomDomainName=$(PROD_DOMAIN_NAME) \
		 	DomainNameZone=$(PROD_DOMAIN_ZONE) \
		 	CertificateArn=$(PROD_CERT_ARN)" \
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
