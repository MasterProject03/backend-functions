#!/bin/bash

cd `dirname "$0"`

# gcloud beta functions deploy accounts --gen2 --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point AccountsHTTP --source .
# gcloud beta functions deploy auth --gen2 --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point AuthHTTP --source .
# gcloud beta functions deploy sources --gen2 --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point SourcesHTTP --source .
# gcloud beta functions deploy posts --gen2 --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point PostsHTTP --source .
# gcloud beta functions deploy submission --gen2 --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point SubmissionHTTP --source .

gcloud functions deploy accounts --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point AccountsHTTP --source .
gcloud functions deploy auth --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point AuthHTTP --source .
gcloud functions deploy sources --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point SourcesHTTP --source .
gcloud functions deploy posts --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point PostsHTTP --source .
gcloud functions deploy submission --trigger-http --allow-unauthenticated --runtime go116 --region europe-west1 --entry-point SubmissionHTTP --source .
