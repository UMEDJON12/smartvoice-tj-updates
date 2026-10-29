#!/usr/bin/env bash
# Run ONLY after owner approval: create a narrowly scoped FCM sender and trust
# only the owner's exact GitHub repository/workflow. No private keys or billing.
set -euo pipefail
sv_project='smartvoice-updates'
sv_number='1074074358850'
sv_repo_id='1434436500'
sv_owner_id='237811306'
sv_pool='smartvoice-github'
sv_provider='github-release'
sv_account='smartvoice-release-notifier@smartvoice-updates.iam.gserviceaccount.com'
sv_role='projects/smartvoice-updates/roles/smartVoiceReleaseSender'
sv_workflow='UMEDJON12/smartvoice-tj-updates/.github/workflows/publish-update-channel.yml@'
sv_owner='umedjonimahmadali42@gmail.com'
sv_active="$(gcloud auth list --filter=status:ACTIVE --format='value(account)')"
[ "$sv_active" = "$sv_owner" ] || { echo 'Wrong Google account; use the project owner account.'; exit 1; }
sv_retry() {
 local sv_attempt
 for sv_attempt in 1 2 3 4 5; do
  if "$@"; then return 0; fi
  if [ "$sv_attempt" -eq 5 ]; then return 1; fi
  sleep 3
 done
}
sv_actual_number="$(gcloud projects describe "$sv_project" --format='value(projectNumber)')"
[ "$sv_actual_number" = "$sv_number" ] || { echo 'Wrong Firebase project'; exit 1; }
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com fcm.googleapis.com --project="$sv_project"
if ! gcloud iam service-accounts describe "$sv_account" --project="$sv_project" >/dev/null 2>&1; then
 gcloud iam service-accounts create smartvoice-release-notifier --project="$sv_project" --display-name='SmartVoice release announcements only'
fi
if ! gcloud iam roles describe smartVoiceReleaseSender --project="$sv_project" >/dev/null 2>&1; then
 gcloud iam roles create smartVoiceReleaseSender --project="$sv_project" --title='SmartVoice FCM sender' --permissions=cloudmessaging.messages.create --stage=GA
fi
# The role is dedicated to this sender. Refuse an unexpectedly broader role.
sv_permissions="$(gcloud iam roles describe smartVoiceReleaseSender --project="$sv_project" --format='csv[no-heading](includedPermissions)')"
[ "$sv_permissions" = 'cloudmessaging.messages.create' ] || { echo 'Unexpected permissions in sender role'; exit 1; }
sv_retry gcloud projects add-iam-policy-binding "$sv_project" --member="serviceAccount:$sv_account" --role="$sv_role" --condition=None >/dev/null
if ! gcloud iam workload-identity-pools describe "$sv_pool" --project="$sv_project" --location=global >/dev/null 2>&1; then
 gcloud iam workload-identity-pools create "$sv_pool" --project="$sv_project" --location=global --display-name='SmartVoice GitHub releases'
fi
sv_mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id,attribute.repository_owner_id=assertion.repository_owner_id,attribute.ref=assertion.ref,attribute.workflow_ref=assertion.workflow_ref,attribute.event_name=assertion.event_name'
# A published release runs at its tag, not refs/heads/main. Reject every
# other event/path; permit manual validate-only from main, and tagged releases.
sv_condition="assertion.repository_id=='$sv_repo_id' && assertion.repository_owner_id=='$sv_owner_id' && assertion.workflow_ref=='$sv_workflow'+assertion.ref && ((assertion.event_name=='release' && assertion.ref.matches('^refs/tags/v[0-9]+[.][0-9]+[.][0-9]+-TJ$')) || (assertion.event_name=='workflow_dispatch' && assertion.ref=='refs/heads/main'))"
if ! gcloud iam workload-identity-pools providers describe "$sv_provider" --project="$sv_project" --location=global --workload-identity-pool="$sv_pool" >/dev/null 2>&1; then
 gcloud iam workload-identity-pools providers create-oidc "$sv_provider" --project="$sv_project" --location=global --workload-identity-pool="$sv_pool" --issuer-uri='https://token.actions.githubusercontent.com' --attribute-mapping="$sv_mapping" --attribute-condition="$sv_condition"
else
 gcloud iam workload-identity-pools providers update-oidc "$sv_provider" --project="$sv_project" --location=global --workload-identity-pool="$sv_pool" --issuer-uri='https://token.actions.githubusercontent.com' --attribute-mapping="$sv_mapping" --attribute-condition="$sv_condition"
fi
sv_retry gcloud iam service-accounts add-iam-policy-binding "$sv_account" --project="$sv_project" --role=roles/iam.workloadIdentityUser --member="principalSet://iam.googleapis.com/projects/$sv_number/locations/global/workloadIdentityPools/$sv_pool/attribute.repository_id/$sv_repo_id" >/dev/null
printf '%s\n' 'SMARTVOICE_FCM_SETUP_OK' 'Настройка прав SmartVoice завершена. Закрытые ключи не создавались.'
