ZIP := bfe-sl.zip
SHELL := /bin/bash
BFE_FUNC_RUNTIME ?= golang123
export BFE_SA
export BFE_FUNC
export BFE_FUNC_RUNTIME
export BFE_ENTRY
export BFE_YDB_ENDPOINT
export BFE_YDB_DATABASE_PATH
export JWT_SECRET_KEY
export BFE_S3_BUCKET_NAME
export BFE_S3_ACCESS_KEY_ID
export BFE_S3_SECRET_ACCESS_KEY
export BFE_ADMIN_USER
export BFE_ADMIN_PASSWORD
export BFE_PRESIGN_TTL_SECONDS
export BFE_ORIGIN_URL
export BFE_SES_ENDPOINT
export BFE_SES_REGION
export BFE_SES_ACCESS_KEY_ID
export BFE_SES_SECRET_ACCESS_KEY
export BFE_EMAIL_FROM
export BFE_APP_LOGIN_URL


git:
	@if [ -z "$(MSG)" ]; then echo 'ERROR: set MSG, e.g. make git MSG="feat: deploy function"'; exit 1; fi
	git add -A
	git commit -m "$(MSG)"
	git push origin main

build-zip:
	rm $(ZIP)
	zip -r $(ZIP) . -x 'patch.diff' '*/patch.diff' '.git/*' '*/.git/*' 'git/*' '*/git/*' '/bfe-sl'





REQUIRED_ENV := BFE_YDB_ENDPOINT BFE_YDB_DATABASE_PATH BFE_JWT_SECRET_KEY BFE_S3_BUCKET_NAME BFE_S3_ACCESS_KEY_ID BFE_S3_SECRET_ACCESS_KEY BFE_ADMIN_USER BFE_ADMIN_PASSWORD BFE_ORIGIN_URL BFE_PRESIGN_TTL_SECONDS BFE_SES_ENDPOINT BFE_SES_REGION BFE_SES_ACCESS_KEY_ID BFE_SES_SECRET_ACCESS_KEY BFE_EMAIL_FROM BFE_APP_LOGIN_URL


check-env:
	@for v in $(REQUIRED_ENV); do \
		val="$${!v}"; \
		if [ -z "$$val" ]; then echo "ERROR: $$v is empty"; exit 1; fi; \
		if printf "%s" "$$val" | LC_ALL=C grep -qP '[\x00-\x1F\x7F,]'; then \
			echo "ERROR: $$v contains newline/control/comma, sanitize it or use Lockbox"; exit 1; \
		fi; \
	done


ENV_ARGS = "YDB_ENDPOINT=$$BFE_YDB_ENDPOINT,YDB_DATABASE_PATH=$$BFE_YDB_DATABASE_PATH,JWT_SECRET_KEY=$$BFE_JWT_SECRET_KEY,S3_BUCKET_NAME=$$BFE_S3_BUCKET_NAME,S3_ACCESS_KEY_ID=$$BFE_S3_ACCESS_KEY_ID,S3_SECRET_ACCESS_KEY=$$BFE_S3_SECRET_ACCESS_KEY,ADMIN_USER=$$BFE_ADMIN_USER,ADMIN_PASSWORD=$$BFE_ADMIN_PASSWORD,ORIGIN_URL=$$BFE_ORIGIN_URL,PRESIGN_TTL_SECONDS=$$BFE_PRESIGN_TTL_SECONDS,SES_ENDPOINT=$$BFE_SES_ENDPOINT,SES_REGION=$$BFE_SES_REGION,SES_ACCESS_KEY_ID=$$BFE_SES_ACCESS_KEY_ID,SES_SECRET_ACCESS_KEY=$$BFE_SES_SECRET_ACCESS_KEY,EMAIL_FROM=$$BFE_EMAIL_FROM,APP_LOGIN_URL=$$BFE_APP_LOGIN_URL"


deploy: check-env build-zip
	yc serverless function version create \
	  --function-name $(BFE_FUNC) \
	  --runtime $(BFE_FUNC_RUNTIME) \
	  --service-account-id $(BFE_SA) \
	  --entrypoint $(BFE_ENTRY) \
	  --source-path ./$(ZIP) \
	  --environment $(ENV_ARGS)
