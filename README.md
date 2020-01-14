# Helm-trivy

This is a small helm plugin that performs vulnerability scans on container images used by charts.
It was inspired by Snyk.io's [helm-snyk](https://github.com/snyk-labs/helm-snyk) plugin. It uses aquasec's [trivy](https://github.com/aquasecurity/trivy) instead of Snyk.io for vulnerability scanning. To be fair, I found in my testing that Snyk had better results, but trivy isn't far (and it's free).

## Installation

Just like any helm plugin, use the `helm plugin` subcommand:

```bash
helm plugin install  https://github.com/ObjectifLibre/helm-trivy
```

Currently avalaible for linux and mac platforms.

## Usage

```bash
Usage: helm trivy [options] <helm chart>
Example: helm trivy -json stable/mariadb

Options:
  -debug
    	Enable debug logging
  -json
    	Enable JSON output
  -nopull
    	Don't pull latest trivy image
  -trivyargs string
    	CLI args to passthrough to trivy
```

Some examples:

Output only high and critical severity vulnerabilities:

```bash
helm trivy -trivyargs '--severity HIGH,CRITICAL' stable/mariadb
```

Get a JSON array with scan results:

```bash
helm trivy -json stable/wordpress
```
