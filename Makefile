.ONESHELL:
.DELETE_ON_ERROR:
.SHELLFLAGS := -eu -o pipefail -c
SHELL := bash
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

CUSTOMER_AWS_ADMIN_PROFILE ?= customer
VENDOR_AWS_ADMIN_PROFILE ?= vendor
ROSA_CLUSTER_NAME ?= invalid-cluster-name
ROSA_USER ?= faas
ROSA_PROXY ?= ""

temp := nocommit
out := bin
rcname := ${ROSA_CLUSTER_NAME}
cpath := ${temp}/${rcname}


all: help

##@ General
.PHONY: help zip

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

${cpath}: # Store ROSA cluster info
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}
	@rosa describe cluster -c ${rcname} -ojson > $@

zip: ## Zip executable in AWS Lambda uploadable format
	@rm -f ${out}/main.zip
	@zip -j ${out}/main.zip ${out}/main

##@ Vendor
.PHONY: vendor-setup vendor-cleanup

${temp}/.for-switch-role-setup: # Setup user who can switch role
	@export AWS_PROFILE=${VENDOR_AWS_ADMIN_PROFILE}

	@echo create switch role user
	@aws iam create-user \
	--user-name for-switch-role > ${temp}/for-switch-role-user

	@echo create access key for switch role user
	@aws iam create-access-key \
	--user-name for-switch-role > ${temp}/for-switch-role-user-access

	@echo create policy for switch role user
	@aws iam create-policy \
	--policy-document file://aws/vendor/for-switch-role-user-policy.json \
	--policy-name for-switch-role-user-policy > ${temp}/for-switch-role-user-policy

	@echo attach policy to switch role user
	@aws iam attach-user-policy \
	--user-name for-switch-role \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/for-switch-role-user-policy)

	touch $@

${temp}/.for-switch-role-cleanup: # Cleanup switch role user
	@export AWS_PROFILE=${VENDOR_AWS_ADMIN_PROFILE}

	@echo detach user policy
	@aws iam detach-user-policy \
	--user-name for-switch-role \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/for-switch-role-user-policy)

	@echo delete user policy
	@aws iam delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/for-switch-role-user-policy)

	@echo delete user access key
	@aws iam delete-access-key \
	--user-name for-switch-role --access-key-id \
	$$(jq -r .AccessKey.AccessKeyId ${temp}/for-switch-role-user-access)

	@echo delete user
	@aws iam delete-user \
	--user-name for-switch-role

	touch $@

${temp}/.switch-role-setup: # Setup role to which user can switch to
	@export AWS_PROFILE=${VENDOR_AWS_ADMIN_PROFILE}

	@echo create switch role
	@user_arn=$$(jq -r .User.Arn ${temp}/for-switch-role-user)
	@aws iam create-role \
	--assume-role-policy-document "$$(jq -c --arg user_arn $$user_arn \
	'.Statement[0].Principal.AWS=$$user_arn' \
	aws/vendor/switch-role-trust-policy.json)" \
	--role-name switch-role > ${temp}/switch-role

	@echo create switch role policy
	@aws iam create-policy \
	--policy-document file://aws/vendor/switch-role-policy.json \
	--policy-name switch-role-policy > ${temp}/switch-role-policy

	@echo attach switch role policy
	@aws iam attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/switch-role-policy) \
	--role-name switch-role

	touch $@

${temp}/.switch-role-cleanup: # Cleanup role which has switch perms to customer roles
	@export AWS_PROFILE=${VENDOR_AWS_ADMIN_PROFILE}

	@echo detach switch role policy
	@aws iam detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/switch-role-policy) \
	--role-name switch-role

	@echo delete switch role policy
	@aws iam delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/switch-role-policy)

	@echo delete switch role
	@aws iam delete-role \
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
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo saving customer get caller identity
	@aws sts get-caller-identity > $@

${temp}/.secret-role-setup: ${temp}/customer-identity # Role which can manage aws secret
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo create secret role
	@role_arn=$$(jq -r .Role.Arn ${temp}/switch-role)
	@aws iam create-role \
	--assume-role-policy-document "$$(jq -c --arg role_arn $$role_arn \
	'.Statement[0].Principal.AWS=$$role_arn' \
	aws/customer/secret-role-trust-policy.json)" \
	--role-name secret-role > ${temp}/secret-role

	@echo create secret role policy
	@account=$$(jq -r .Account ${temp}/customer-identity)
	@secret_res="arn:aws:secretsmanager:*:$$account:secret:faas-*"
	@aws iam create-policy \
	--policy-document "$$(jq -c --arg secret_res $$secret_res \
	'.Statement[0].Resource=$$secret_res' \
	aws/customer/secret-role-policy.json)" \
	--policy-name secret-role-policy > ${temp}/secret-role-policy

	@echo attach secret role policy
	@aws iam attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/secret-role-policy) \
	--role-name secret-role

	touch $@

${temp}/.secret-role-cleanup: # Remove role which manage aws secrets
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo detach secret role policy
	@aws iam detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/secret-role-policy) \
	--role-name secret-role

	@echo delete secret role policy
	@aws iam delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/secret-role-policy) \

	@echo delete secret role
	@aws iam delete-role \
	--role-name secret-role

	touch $@

${temp}/.lambda-role-setup: ${temp}/customer-identity # Role which can manage aws lambda
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo create lambda role
	@role_arn=$$(jq -r .Role.Arn ${temp}/switch-role)
	@aws iam create-role \
	--assume-role-policy-document "$$(jq -c --arg role_arn $$role_arn \
	'.Statement[0].Principal.AWS=$$role_arn' \
	aws/customer/lambda-role-trust-policy.json)" \
	--role-name lambda-role > ${temp}/lambda-role

	@echo create lambda role policy
	@account=$$(jq -r .Account ${temp}/customer-identity)
	@lambda_res="arn:aws:lambda:*:$$account:function:faas-*"
	@aws iam create-policy \
	--policy-document "$$(jq -c --arg lambda_res $$lambda_res \
	'.Statement[0].Resource=$$lambda_res' \
	aws/customer/lambda-role-policy.json)" \
	--policy-name lambda-role-policy > ${temp}/lambda-role-policy

	@echo attach lambda role policy
	@aws iam attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-role-policy) \
	--role-name lambda-role

	touch $@

${temp}/.lambda-role-cleanup: # Remove role which manages aws lambda # Save caller identity
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo detach lambda role policy
	@aws iam detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-role-policy) \
	--role-name lambda-role

	@echo delete lambda role policy
	@aws iam delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-role-policy) \

	@echo delete lambda role
	@aws iam delete-role \
	--role-name lambda-role

	touch $@

${temp}/.lambda-exec-role-setup: # Role which'll be used lambda during runtime
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo create lambda execution role
	@aws iam create-role \
	--assume-role-policy-document file://aws/customer/lambda-trust-policy.json \
	--role-name lambda-exec-role > ${temp}/lambda-exec-role

	@echo create lambda execution role policy
	@aws iam create-policy \
	--policy-document file://aws/customer/lambda-exec-role-policy.json \
	--policy-name lambda-exe-role-policy > ${temp}/lambda-exec-role-policy

	@echo attach lambda exec role policy
	@aws iam attach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-exec-role-policy) \
	--role-name lambda-exec-role

	touch $@

${temp}/.lambda-exec-role-cleanup: # Remove lambda runtime role
	@export AWS_PROFILE=${CUSTOMER_AWS_ADMIN_PROFILE}

	@echo detach lambda execution role policy
	@aws iam detach-role-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-exec-role-policy) \
	--role-name lambda-exec-role

	@echo delete lambda execution role policy
	@aws iam delete-policy \
	--policy-arn $$(jq -r .Policy.Arn ${temp}/lambda-exec-role-policy) \

	@echo delete lambda execution role
	@aws iam delete-role \
	--role-name lambda-exec-role

	touch $@

customer := secret lambda lambda-exec
customer-setup-targets :=  $(foreach t,$(customer),${temp}/.$(t)-role-setup)
customer-cleanup-targets :=  $(foreach t,$(customer),${temp}/.$(t)-role-cleanup)

customer-setup: $(customer-setup-targets)  ## Setup necessary permissions for customer to use faas
	@rm -f $(customer-cleanup-targets)

customer-cleanup: $(customer-cleanup-targets)  ## Cleanup permissions for customer to stop using faas
	@rm -f ${temp}/secret-*
	@rm -f ${temp}/lambda-*
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

	touch $@

profile-setup: ${temp}/aws ## Setup profile for vendor to assume customer roles
profile-cleanup: ## Cleanup profile of vendor which assumes customer roles
	@rm -f ${temp}/aws*

##@ ROSA User Operations
.PHONY: rosa-user-setup rosa-user-cleanup

${temp}/.${rcname}-setup-password: # Generates a password for rosa user
	@password=$$(cat /dev/urandom | tr -dc A-Za-z0-9 | head -c 20 | sed -re 's,(.{5}),\1-,g' -e 's,-$$,,')
	@echo $$password > $@

# TODO: make idempotent if possible
${temp}/.${rcname}-setup-user: ${temp}/.${rcname}-setup-password # Creates and add user to dedicated-admin group
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=secret-role

	@rosa create idp \
	-c ${rcname} -t htpasswd --username ${ROSA_USER} \
	--password $$(cat $<) -y

	@rosa grant user dedicated-admin -c ${rcname} -u ${ROSA_USER}

	touch $@

# TODO: delete idp only if no other user exists
${temp}/.${rcname}-cleanup-user:
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=secret-role

	@rosa revoke user \
	dedicated-admins --user=${ROSA_USER} --cluster=${rcname} -y

	@rosa delete idp htpasswd --cluster=${rcname} -y

	touch $@

rosa-setup-targets := ${cpath} ${temp}/.${rcname}-setup-user
rosa-cleanup-targets := ${cpath} ${temp}/.${rcname}-cleanup-user

rosa-user-setup: $(rosa-setup-targets) ## Setup a user in dedicated admin group with htpasswd idp
	@rm -f $(rosa-cleanup-targets)

rosa-user-cleanup: $(rosa-cleanup-targets) ## Cleanup user from dedicated admin group along with htpasswd idp
	@rm -f $(rosa-setup-targets)
	@rm -f ${temp}/.${rcname}-setup-password
	@rm -f ${cpath}

##@ AWS Lambda
.PHONY: secret-setup secret-cleanup lambda-setup lambda-cleanup remote-deploy \
	remote-run stop-lambda restart-lambda local-deploy local-run

${temp}/.secret-setup: ${cpath} # Upload rosa user creds to AWS Secretsmanager
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=secret-role

	@secret=faas-${rcname}

	@pass=$$(cat ${temp}/.${rcname}-setup-password)
	@aws secretsmanager create-secret \
	--name $$secret --secret-string \
	"$$(jq -nc --arg user "${ROSA_USER}" --arg pass "$$pass" \
		'{"username": $$user, "password": $$pass}')"

	@lambda_arn=$$(jq -r .Role.Arn ${temp}/lambda-exec-role)
	@aws secretsmanager put-resource-policy \
	--secret-id $$secret --resource-policy \
	"$$(jq -c --arg lambda_arn $$lambda_arn \
	'.Statement.Principal.AWS=$$lambda_arn' \
	aws/customer/secret-allow-lambda-access.json)"

	touch $@

${temp}/.secret-cleanup: ${cpath} # Delete rosa user creds in AWS Secretsmanager
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=secret-role

	@secret=faas-${rcname}
	@aws secretsmanager delete-secret \
	--secret-id=$$secret --force-delete-without-recovery

	touch $@

secret-setup-targets := ${temp}/.secret-setup
secret-cleanup-targets := ${temp}/.secret-cleanup

secret-setup: $(secret-setup-targets) ## Setup lambda to access rosa user creds in AWS Secretsmanager
	@rm -f $(secret-cleanup-targets)

secret-cleanup: $(secret-cleanup-targets) ## Remove rosa user creds secret from AWS Secretsmanager
	@rm -f $(secret-setup-targets)

${temp}/.lambda-setup: ${cpath} build # Upload lambda code
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=lambda-role

	@infra_id=$$(jq -r .infra_id ${cpath})
	@subnets=$$(aws ec2 describe-instances \
	  --filters Name=tag:Name,Values=$$infra_id-master-* \
	  --query 'Reservations[*].Instances[*].SubnetId' \
	  | jq -r '.[]|.[]' | sed -rze 's/\n/,/g' -e 's|,$$||')
	@sgs=$$(aws ec2 describe-instances \
	  --filters Name=tag:Name,Values=$$infra_id-master-* \
	  --query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' \
	  | jq -r '.[]|.[]|.[]' | sed -rze 's/\n/,/g' -e 's|,$$||')

	@lambda_arn=$$(jq -r .Role.Arn ${temp}/lambda-exec-role)
	@aws lambda create-function \
	--runtime go1.x --role $$lambda_arn --handle main \
	--vpc-config SubnetIds=$$subnets,SecurityGroupIds=$$sgs \
	--zip-file fileb://${out}/main.zip \
	--function-name faas-${rcname} > ${temp}/.faas-${rcname}

	touch $@

${temp}/.lambda-cleanup: ${cpath} # Delete lambda code
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=lambda-role

	@aws logs delete-log-group --log-group-name /aws/lambda/faas-${rcname}
	@aws lambda delete-function --function-name faas-${rcname}

	touch $@

lambda-setup-targets := ${temp}/.lambda-setup
lambda-cleanup-targets := ${temp}/.lambda-cleanup

lambda-setup: $(lambda-setup-targets) ## Create lambda function
	@rm -f $(lambda-cleanup-targets)

lambda-cleanup: $(lambda-cleanup-targets) ## Delete lambda function
	@rm -f $(lambda-setup-targets)
	@rm -f ${temp}/.faas-${rcname}
	@rm -f ${temp}/response.json

# quickly select with what payload we want to invoke lambda function
payloads = apply create remove
define payload_template =
payload-$(1):
	@ln -srf ${temp}/$$@.json ${temp}/payload.json
	@echo Current payload is set to [${temp}/$$@.json]
endef
$(foreach load,$(payloads),$(eval $(call payload_template,$(load))))

remote-deploy: ${cpath} build ## Deploy lambda on AWS
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=lambda-role

	@aws lambda update-function-code \
	  --function-name faas-${rcname} --zip-file fileb://${out}/main.zip > /dev/null

remote-run: ${cpath} ## Invoke lambda on AWS
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=lambda-role

	@aws lambda invoke \
	  --cli-binary-format raw-in-base64-out \
	  --payload "$$(jq -c . ${temp}/payload.json)" \
	  --function-name faas-${rcname} \
	  ${temp}/response.json

stop-lambda: ## Stop lambda rie in docker
	@docker rm lambda -f >/dev/null 2>&1

restart-lambda: stop-lambda ## (Re)start lambda rie in docker
	@docker run --name lambda -d --restart on-failure \
	-p 9001:8080 \
	-v $(PWD)/bin:/var/task:ro,delegated \
	-v $(PWD)/${temp}/aws-config:/root/.aws/config:ro,delegated \
	-v $(PWD)/${temp}/aws-creds:/root/.aws/credentials:ro,delegated \
	-e AWS_REGION=$$(jq -r .region.id ${cpath}) \
	-e AWS_PROFILE=secret-role \
	-e ROSA_PROXY=${ROSA_PROXY} \
	public.ecr.aws/lambda/go:1 main >/dev/null

local-deploy: build restart-lambda ## Deploy lambda in docker

local-run: ## Invoke lambda in docker
	@export AWS_CONFIG_FILE=${temp}/aws-config
	@export AWS_SHARED_CREDENTIALS_FILE=${temp}/aws-creds
	@export AWS_REGION=$$(jq -r .region.id ${cpath})
	@export AWS_PROFILE=lambda-role

	@aws lambda invoke \
	  --cli-binary-format raw-in-base64-out \
	  --payload "$$(jq -c . ${temp}/payload.json)" \
	  --function-name function \
	  ${temp}/response.json \
	  --endpoint http://localhost:9001 --no-sign-request

##@ Golang
.PHONY: vet test lint build

vet: ## Run go vet
	go vet ./...

test: ## Run unit tests
	go test ./... -coverprofile ${temp}/cover.out

lint: ## Run golangci-lint
	@docker run --rm -t -v $(PWD):/app:ro -v "$$(go env GOCACHE):/root/.cache" \
	 -w /app golangci/golangci-lint:v1.51.0 golangci-lint run -v --timeout=3m

build: vet ## Build without symbols
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/main main.go
	@$(MAKE) -s zip