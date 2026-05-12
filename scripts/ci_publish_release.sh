#!/usr/bin/env bash
set -euo pipefail

version="${RELEASE_VERSION:-$(tr -d '[:space:]' < VERSION)}"
tag="${RELEASE_TAG:-v${version}}"
notes_file="dist/release_notes.md"

if [[ ! -f "${notes_file}" ]]; then
  echo "Missing ${notes_file}" >&2
  exit 1
fi

api="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}"
package_name="simple-idm"
package_base_url="${api}/packages/generic/${package_name}/${version}"

curl --silent --show-error --fail \
  --request POST \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --form "tag_name=${tag}" \
  --form "ref=${CI_COMMIT_SHA}" \
  "${api}/repository/tags" >/dev/null || true

if curl --silent --show-error --fail \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  "${api}/releases/${tag}" >/dev/null 2>&1; then
  curl --silent --show-error --fail \
    --request PUT \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    --form "name=Release ${tag}" \
    --form "description=<${notes_file}" \
    "${api}/releases/${tag}" >/dev/null
else
  curl --silent --show-error --fail \
    --request POST \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    --form "tag_name=${tag}" \
    --form "ref=${CI_COMMIT_SHA}" \
    --form "name=Release ${tag}" \
    --form "description=<${notes_file}" \
    "${api}/releases" >/dev/null
fi

for package_file in dist/simple-idm-"${version}"-*.tar.gz; do
  [[ -f "${package_file}" ]] || continue
  file_name="$(basename "${package_file}")"
  asset_name="${file_name%.tar.gz}"
  package_url="${package_base_url}/${file_name}"

  echo "Uploading ${file_name} to GitLab Generic Package Registry"
  curl --silent --show-error --fail \
    --request PUT \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    --upload-file "${package_file}" \
    "${package_url}" >/dev/null

  curl --silent --show-error \
    --request POST \
    --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
    --form "name=${asset_name}" \
    --form "url=${package_url}" \
    --form "link_type=package" \
    "${api}/releases/${tag}/assets/links" >/dev/null || true
done

if [[ -n "${RELEASE_PUSH_TOKEN:-}" && -f dist/CHANGELOG.generated.md && -n "${CI_COMMIT_BRANCH:-}" ]]; then
  git config user.name "${GITLAB_USER_NAME:-GitLab CI}"
  git config user.email "${GITLAB_USER_EMAIL:-gitlab-ci@${CI_SERVER_HOST}}"
  git checkout -B "${CI_COMMIT_BRANCH}" "${CI_COMMIT_SHA}"
  cp dist/CHANGELOG.generated.md CHANGELOG.md
  if ! git diff --quiet -- CHANGELOG.md; then
    git add CHANGELOG.md
    git commit -m "docs: update changelog for ${tag} [skip ci]"
    git push "https://oauth2:${RELEASE_PUSH_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" "HEAD:${CI_COMMIT_BRANCH}"
  fi
else
  echo "Skipping CHANGELOG.md push. Set RELEASE_PUSH_TOKEN to enable it."
fi

echo "Published GitLab release ${tag}"
