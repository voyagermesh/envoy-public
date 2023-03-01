#!/bin/bash -e

AZP_BRANCH="${AZP_BRANCH:-}"
ENVOY_GIT_USERNAME="${ENVOY_GIT_USERNAME:-envoy-bot}"
ENVOY_GIT_EMAIL="${ENVOY_GIT_EMAIL:-envoy-bot@users.noreply.github.com}"
ENVOY_RELEASE_VERSION="${ENVOY_RELEASE_VERSION:-}"

MAIN_BRANCH=refs/heads/main


if [[ "$AZP_BRANCH" != "$MAIN_BRANCH" ]]; then
    # shellcheck disable=SC2016
    echo '$AZP_BRANCH must be set to the `main` branch, exiting' >&2
    # exit 1
fi

# DEBUGGING
echo 1.26.0 > VERSION.txt


configure_git_user () {
    if [[ -z "$ENVOY_GIT_USERNAME" || -z "$ENVOY_GIT_EMAIL" ]]; then
        echo 'Unable to set git name/email, using existing git config' >&2
        return
    fi
    git config --global user.name "$ENVOY_GIT_USERNAME"
    git config --global user.email "$ENVOY_GIT_EMAIL"
}

create_dev_commit () {
    bazel run @envoy_repo//:dev -- --patch
}

get_release_name () {
    local version
    if [[ -z "$ENVOY_RELEASE_VERSION" ]]; then
        version="$(cat VERSION.txt | cut -d- -f1 | cut -d. -f-2)"
    else
        version="$ENVOY_RELEASE_VERSION"
    fi
    echo -n "TEST.release/v${version}"
}

create_branch () {
    local release_name commit_sha
    release_name="$(get_release_name)"
    commit_sha="$(git rev-parse HEAD)"

    echo "Creating ${release_name} from ${commit_sha}"
    git checkout -b "$release_name"
    git push origin "$release_name"
}

create_release_branch () {
    configure_git_user
    create_dev_commit
    create_branch
}

create_release_branch
