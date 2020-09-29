#!/bin/bash

function trivy_scan(){
  # Fetch unique images from pods
  images=$(kubectl get pods -n "${NAMESPACE}" -o jsonpath="{..imageID}" |tr -s '[[:space:]]' '\n' |sort |uniq)
  # Splitting into images list
  images_list=($(echo "${images}" | tr " " "\n"))

  for image in "${images_list[@]}"; 
  do
    # Filter SHA id from image ID
    image_sha_id=$(sed -e 's#.*docker-pullable://\(\)#\1#' <<< "${image}")
    # Get image name from SHA ID
    image_name=$(docker inspect "${image_sha_id}" | jq -r '.[0].RepoTags | first')
    # Run trivy to fetch high,critical vulnerability details for each image
    trivy --exit-code 1 --severity HIGH,CRITICAL "${image_name}"
    EXITCODE=$?
    if [ $EXITCODE -eq 1 ]; then
      # Write vulnerability details to log file
      trivy "${image_name}" >> trivy_report.log
    fi
  done

  if [ -s /trivy_report.log ]; then
    # Trigger slack alert if vulnerabilities found
    curl -F file=@trivy_report.log -F "initial_comment=Trivy report for $KUBE_CONTEXT on `date`" -F channels=$TRIVY_SLACK_CHANNEL_ID -H "Authorization: Bearer `$TRIVY_SLACK_TOKEN`" https://slack.com/api/files.upload
  fi
}

trivy_scan