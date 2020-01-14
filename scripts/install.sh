#! /bin/bash -e

version="$(cat plugin.yaml | grep "version" | cut -d '"' -f 2)"
latest_version=$(curl -Is "https://github.com/ObjectifLibre/helm-trivy/releases/latest" | grep "Location" | cut -d'/' -f 8 | tr -d "\r")

echo "Installing helm-trivy ${latest_version} ..."

mkdir -p $HELM_PLUGIN_DIR
cd $HELM_PLUGIN_DIR

unameOut="$(uname -s)"

case "${unameOut}" in
    Linux*)     os=linux;;
    Darwin*)    os=macos;;
    *)          os="UNKNOWN:${unameOut}"
esac

arch=`uname -m`
url="https://github.com/ObjectifLibre/helm-trivy/releases/download/${latest_version}/helm-trivy-${os}"

if [ "$url" = "" ]
then
    echo "Unsupported OS / architecture: ${os}_${arch}"
    exit 1
fi

filename="helm-trivy-${os}"

if [ -n $(command -v curl) ]
then
    curl -sSL -O $url
elif [ -n $(command -v wget) ]
then
    wget -q $url
else
    echo "Need curl or wget"
    exit -1
fi

rm -rf bin && mkdir bin && mv $filename ./bin/$filename
chmod a+x ./bin/$filename

echo "helm-trivy ${latest_version} is installed."
echo
echo "See https://github.com/ObjectifLibre/helm-trivy for help getting started."
