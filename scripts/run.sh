#! /bin/bash -e

unameOut="$(uname -s)"

case "${unameOut}" in
    Linux*)     os=linux;;
    Darwin*)    os=macos;;
    *)          os="UNKNOWN:${unameOut}"
esac

filename="helm-trivy-${os}"
$HELM_PLUGIN_DIR/bin/$filename "$@"
