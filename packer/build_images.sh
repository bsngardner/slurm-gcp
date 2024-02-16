#!/bin/bash
IMAGE=$1
if [ -z $IMAGE ]; then
    echo "I need an image to build, look into build to select one"
    exit 1
fi
if [ ! -f builds/$IMAGE.hcl ]; then
    echo "Build information for $IMAGE does not exists, ensure that you have the corresponding file builds/$IMAGE.hcl"
    exit 1
fi
VERSION=$2
if [ -z $VERSION ]; then
    echo "I need a version to build, something like 6.2"
    exit 1
fi
#If you want to publish instead of build, set this to yes
PUBLISH=${3:-no}
#$4 if specified is the slurm_version
if [ ! -z $4 ]; then
    SLURM_VERSION="-var \"slurm_version=$4\""
fi
EXTRA_VARS=""

SLURM_GCP_PROJECT="schedmd-slurm-public"
image_list_file="/tmp/images.list"
testing_members=("group:hpc-toolkit-eng@google.com" "serviceAccount:508417052821-compute@developer.gserviceaccount.com" "serviceAccount:508417052821@cloudbuild.gserviceaccount.com")

if [ "x$PUBLISH" == "xno" ]; then
    packer build -var-file builds/$IMAGE.hcl -var "project_id=$SLURM_GCP_PROJECT" -var "slurmgcp_version=$VERSION" -var 'image_licenses=["projects/schedmd-slurm-public/global/licenses/schedmd-slurm-gcp-free-plan"]' $SLURM_VERSION $EXTRA_VARS .
    last_run=$(jq -r '.last_run_uuid' manifest.json)
    publish_image=$(jq -r --arg last_run_uuid "$last_run" '.builds[] | select(.packer_run_uuid == $last_run_uuid) | .artifact_id' manifest.json)
    echo "Modify image description"
    gcloud compute images update $publish_image --description="Public Slurm image based on the $IMAGE image" --project="$SLURM_GCP_PROJECT"
    echo "generated image \"$publish_image\""
    echo $publish_image >> $image_list_file
    #Add permissions only to Google testers
    for member in "${testing_members[@]}"; do
        echo "Add $member compute.imageUser to $publish_image"
        gcloud compute images add-iam-policy-binding $publish_image --member="$member" --role='roles/compute.imageUser' --project="$SLURM_GCP_PROJECT"
        echo "Add $member compute.viewer to $publish_image"
        gcloud compute images add-iam-policy-binding $publish_image --member="$member" --role='roles/compute.viewer' --project="$SLURM_GCP_PROJECT"
    done
else
    for p_image in $(<$image_list_file); do
        echo "Working on $p_image"
        echo "Adding public roles"
        gcloud compute images add-iam-policy-binding $p_image --member='allAuthenticatedUsers' --role='roles/compute.imageUser' --project="$SLURM_GCP_PROJECT"
        gcloud compute images add-iam-policy-binding $p_image --member='allAuthenticatedUsers' --role='roles/compute.viewer' --project="$SLURM_GCP_PROJECT"
        echo "Removing testing roles"
        for member in "${testing_members[@]}"; do
            gcloud compute images remove-iam-policy-binding $p_image --member="$member" --role='roles/compute.imageUser' --project="$SLURM_GCP_PROJECT"
            gcloud compute images remove-iam-policy-binding $p_image --member="$member" --role='roles/compute.viewer' --project="$SLURM_GCP_PROJECT"
        done
    done
    mv $image_list_file ${image_list_file}.old
fi
