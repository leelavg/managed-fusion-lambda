.ONESHELL:
.DELETE_ON_ERROR:
.SHELLFLAGS := -eu -o pipefail -c
SHELL := bash
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

CUSTOMER_AWS_ADMIN_PROFILE ?= customer
VENDOR_AWS_ADMIN_PROFILE ?= vendor
ROSA_CLUSTER_NAME ?= invalid-cluster-name

temp := nocommit

all: help

##@ General
.PHONY: help

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

${temp}/${ROSA_CLUSTER_NAME}: # Store ROSA cluster info
	@rosa describe --profile ${CUSTOMER_AWS_ADMIN_PROFILE} \
	cluster -c ${ROSA_CLUSTER_NAME} -ojson > $@

##@ Vendor
.PHONY: vendor-setup vendor-cleanup

${temp}/.for-switch-role-setup: # Setup user who can switch role
	@echo create switch role user
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} create-user \
	--user-name for-switch-role > ${temp}/for-switch-role-user

	@echo create access key for switch role user
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} create-access-key \
	--user-name for-switch-role > ${temp}/for-switch-role-user-access

	@echo create policy for switch role user
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} create-policy \
	--policy-document file://aws/vendor/for-switch-role-user-policy.json \
	--policy-name for-switch-role-user-policy > ${temp}/for-switch-role-user-policy

	@echo attach policy to switch role user
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} attach-user-policy \
	--user-name for-switch-role \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/for-switch-role-user-policy)

	touch $@

${temp}/.for-switch-role-cleanup: # Cleanup switch role user
	@echo detach user policy
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} detach-user-policy \
	--user-name for-switch-role \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/for-switch-role-user-policy)

	@echo delete user policy
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/for-switch-role-user-policy)

	@echo delete user access key
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} delete-access-key \
	--user-name for-switch-role --access-key-id \
	$$(jq -r .AccessKey.AccessKeyId ${temp}/for-switch-role-user-access)

	@echo delete user
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} delete-user \
	--user-name for-switch-role

	touch $@

${temp}/.switch-role-setup: # Setup role to which user can switch to
	@echo create switch role
	@user_arn=$$(jq -r .User.Arn ${temp}/for-switch-role-user)
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} create-role \
	--assume-role-policy-document "$$(jq -c --arg user_arn $$user_arn \
	'.Statement[0].Principal.AWS=$$user_arn' \
	aws/vendor/switch-role-trust-policy.json)" \
	--role-name switch-role > ${temp}/switch-role

	@echo create switch role policy
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} create-policy \
	--policy-document file://aws/vendor/switch-role-policy.json \
	--policy-name switch-role-policy > ${temp}/switch-role-policy

	@echo attach switch role policy
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/switch-role-policy) \
	--role-name switch-role

	touch $@

${temp}/.switch-role-cleanup: # Cleanup role which has switch perms to customer roles
	@echo detach switch role policy
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/switch-role-policy) \
	--role-name switch-role

	@echo delete switch role policy
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/switch-role-policy)

	@echo delete switch role
	@aws iam --profile ${VENDOR_AWS_ADMIN_PROFILE} delete-role \
	--role-name switch-role

	touch $@

vendor := for-switch switch
vendor-setup-targets := $(foreach t,$(vendor),${temp}/.$(t)-role-setup)
vendor-cleanup-targets := $(foreach t,$(vendor),${temp}/.$(t)-role-cleanup)

vendor-setup: $(vendor-setup-targets) ## Setup necessary permissions for vendor to assume customer roles
	@rm -f $(vendor-cleanup-targets)

vendor-cleanup: $(vendor-cleanup-targets) ## Cleanup permissions for vendor assuming customer roles
	@rm -f ${temp}/for-switch-role*
	@rm -f ${temp}/switch-role*
	@rm -f $(vendor-setup-targets)

##@ Customer
.PHONY: customer-setup customer-cleanup

${temp}/customer-identity: # Save caller identity
	@echo saving customer get caller identity
	@aws sts --profile ${CUSTOMER_AWS_ADMIN_PROFILE} \
	get-caller-identity > $@

${temp}/.secret-role-setup: ${temp}/customer-identity # Role which can manage aws secret
	@echo create secret role
	@role_arn=$$(jq -r .Role.Arn ${temp}/switch-role)
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-role \
	--assume-role-policy-document "$$(jq -c --arg role_arn $$role_arn \
	'.Statement[0].Principal.AWS=$$role_arn' \
	aws/customer/secret-role-trust-policy.json)" \
	--role-name secret-role > ${temp}/secret-role

	@echo create secret role policy
	@account=$$(jq -r .Account ${temp}/customer-identity)
	@secret_res="arn:aws:secretsmanager:*:$$account:secret:fass-*"
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-policy \
	--policy-document "$$(jq -c --arg secret_res $$secret_res \
	'.Statement[0].Resource=$$secret_res' \
	aws/customer/secret-role-policy.json)" \
	--policy-name secret-role-policy > ${temp}/secret-role-policy

	@echo attach secret role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/secret-role-policy) \
	--role-name secret-role

	touch $@

${temp}/.secret-role-cleanup: # Remove role which manage aws secrets
	@echo detach secret role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/secret-role-policy) \
	--role-name secret-role

	@echo delete secret role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/secret-role-policy) \

	@echo delete secret role
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-role \
	--role-name secret-role

	touch $@

${temp}/.lambda-role-setup: ${temp}/customer-identity # Role which can manage aws lambda
	@echo create lambda role
	@role_arn=$$(jq -r .Role.Arn ${temp}/switch-role)
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-role \
	--assume-role-policy-document "$$(jq -c --arg role_arn $$role_arn \
	'.Statement[0].Principal.AWS=$$role_arn' \
	aws/customer/lambda-role-trust-policy.json)" \
	--role-name lambda-role > ${temp}/lambda-role

	@echo create lambda role policy
	@account=$$(jq -r .Account ${temp}/customer-identity)
	@lambda_res="arn:aws:lambda:*:$$account:function:fass-*"
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-policy \
	--policy-document "$$(jq -c --arg lambda_res $$lambda_res \
	'.Statement[0].Resource=$$lambda_res' \
	aws/customer/lambda-role-policy.json)" \
	--policy-name lambda-role-policy > ${temp}/lambda-role-policy

	@echo attach lambda role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-role-policy) \
	--role-name lambda-role

	touch $@

${temp}/.lambda-role-cleanup: # Remove role which manages aws lambda # Save caller identity
	@echo detach lambda role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-role-policy) \
	--role-name lambda-role

	@echo delete lambda role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-role-policy) \

	@echo delete lambda role
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-role \
	--role-name lambda-role

	touch $@

${temp}/.lambda-exec-role-setup: # Role which'll be used lambda during runtime
	@echo create lambda execution role
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-role \
	--assume-role-policy-document file://aws/customer/lambda-trust-policy.json \
	--role-name lambda-exec-role > ${temp}/lambda-exec-role

	@echo create lambda execution role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-policy \
	--policy-document file://aws/customer/lambda-exec-role-policy.json \
	--policy-name lambda-exe-role-policy > ${temp}/lambda-exec-role-policy

	@echo attach lambda exec role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-exec-role-policy) \
	--role-name lambda-exec-role

	touch $@

${temp}/.lambda-exec-role-cleanup: # Remove lambda runtime role
	@echo detach lambda execution role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-exec-role-policy) \
	--role-name lambda-exec-role

	@echo delete lambda execution role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-exec-role-policy) \

	@echo delete lambda execution role
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-role \
	--role-name lambda-exec-role

	touch $@

${temp}/.ec2-describe-role-setup: # Role to get subnets & security groups attached to ec2
	@echo create ec2 describe role
	@role_arn=$$(jq -r .Role.Arn ${temp}/switch-role)
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-role \
	--assume-role-policy-document "$$(jq -c --arg role_arn $$role_arn \
	'.Statement[0].Principal.AWS=$$role_arn' \
	aws/customer/ec2-describe-trust-policy.json)" \
	--role-name ec2-describe-role > ${temp}/ec2-describe-role

	@echo create ec2 describe role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} create-policy \
	--policy-document file://aws/customer/ec2-describe-role-policy.json \
	--policy-name ec2-describe-role-policy > ${temp}/ec2-describe-role-policy

	@echo attach ec2 describe role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/ec2-describe-role-policy) \
	--role-name ec2-describe-role

	touch $@

${temp}/.ec2-describe-role-cleanup: # Cleanup role which can query subnets & SGs of ec2
	@echo detach ec2 describe role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/ec2-describe-role-policy) \
	--role-name ec2-describe-role

	@echo delete ec2 describe role policy
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/ec2-describe-role-policy)

	@echo delete ec2 describe role
	@aws iam --profile ${CUSTOMER_AWS_ADMIN_PROFILE} delete-role \
	--role-name ec2-describe-role

	touch $@

customer := secret lambda lambda-exec ec2-describe
customer-setup-targets :=  $(foreach t,$(customer),${temp}/.$(t)-role-setup)
customer-cleanup-targets :=  $(foreach t,$(customer),${temp}/.$(t)-role-cleanup)

customer-setup: $(customer-setup-targets)  ## Setup necessary permissions for customer to use faas
	@rm -f $(customer-cleanup-targets)

customer-cleanup: $(customer-cleanup-targets)  ## Cleanup permissions for customer to stop using faas
	@rm -f ${temp}/secret-*
	@rm -f ${temp}/lambda-*
	@rm -f ${temp}/ec2-describe-*
	@rm -f ${temp}/customer-identity
	@rm -f $(customer-setup-targets)

##@ AWS Access

${temp}/aws: # Create aws config and credentials files for role chaining
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds

	@echo creating vendor user profile
	@key_id=$$(jq -r .AccessKey.AccessKeyId ${temp}/for-switch-role-user-access)
	@key_secret=$$(jq -r .AccessKey.SecretAccessKey ${temp}/for-switch-role-user-access)
	@aws configure set aws_access_key_id $${key_id} --profile vendor-user
	@aws configure set aws_secret_access_key $${key_secret} --profile vendor-user
	@aws configure set region us-west-2 --profile vendor-user

	@echo creating switch role profile
	@switch_role_arn=$$(jq -r .Role.Arn ${temp}/switch-role)
	@aws configure set role_arn $${switch_role_arn} --profile switch-role
	@aws configure set source_profile vendor-user --profile switch-role

	@echo creating secret role profile
	@secret_role_arn=$$(jq -r .Role.Arn ${temp}/secret-role)
	@aws configure set role_arn $${secret_role_arn} --profile secret-role
	@aws configure set source_profile switch-role --profile secret-role

	@echo creating lambda role profile
	@lambda_role_arn=$$(jq -r .Role.Arn ${temp}/lambda-role)
	@aws configure set role_arn $${lambda_role_arn} --profile lambda-role
	@aws configure set source_profile switch-role --profile lambda-role

	@echo creating lambda exec role profile
	@lambda_exec_role_arn=$$(jq -r .Role.Arn ${temp}/lambda-exec-role)
	@aws configure set role_arn $${lambda_exec_role_arn} --profile lambda-exec-role
	@aws configure set source_profile switch-role --profile lambda-exec-role

	@echo creating ec2 describe role profile
	@ec2_describe_role_arn=$$(jq -r .Role.Arn ${temp}/ec2-describe-role)
	@aws configure set role_arn $${ec2_describe_role_arn} --profile ec2-describe-role
	@aws configure set source_profile switch-role --profile ec2-describe-role

	touch $@

setup-profile: ${temp}/aws ## Setup profile for vendor to assume customer roles
cleanup-profile: ## Cleanup profile of vendor which assumes customer roles
	@rm -f ${temp}/aws*

describe-instances: ${temp}/aws
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds

	@aws ec2 describe-instances --profile ec2-describe-role --region ap-northeast-3