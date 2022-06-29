#!/bin/bash

cd `dirname "$0"`

gcloud functions deploy accounts --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point AccountsHTTP --source . --env-vars-file .env.yaml
gcloud functions deploy auth --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point AuthHTTP --source . --env-vars-file .env.yaml
gcloud functions deploy sources --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point SourcesHTTP --source . --env-vars-file .env.yaml
gcloud functions deploy posts --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point PostsHTTP --source . --env-vars-file .env.yaml
gcloud functions deploy submission --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point SubmissionHTTP --source . --env-vars-file .env.yaml
