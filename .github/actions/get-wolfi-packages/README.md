# Wolfi Packages Updater

This action retrieves package versions from the [**Wolfi APKINDEX**](https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz) and serves per-package JSON files based on a provided Wolfi image file in `tmp/wolfi-packages/`.

Currently, the action is based on the fact that packages are delivered at the same time on both `x86_64` and `arm64` architecture. This behavior will be adjusted later if the datasource is retained.


## 🛠 How It Works

1. **Input**

   The `wolfi_packages.py` script expects a Wolfi template file path as an argument:
     ```bash
     python wolfi_packages.py <path-to-wolfi-image-file>
     ```
   The Wolfi template should define packages like this (format is YAML):
     ```yaml
     contents:
       packages:
         - nginx=v1.2.3-r4
         - openssl=v1.2.6-r2
     ```

2. **Output**

   For each package listed in the YAML file, a JSON file containing all the versions found in **APKINDEX** is written to:
     ```
     /tmp/wolfi-packages/<package-name>.json
     ```
   Example for nginx:
     ```
     /tmp/wolfi-packages/nginx.json
     ```
   Content of the file:
     ```json
     [
       "1.24.0-r2",
       "1.25.2-r0",
       "1.25.3-r0",
       "1.25.3-r1"
     ]
     ```

3. **Usage**

   If using the renovate action, serve the file to renovate container by adding a [`docker-volumes` parameter](https://github.com/renovatebot/github-action?tab=readme-ov-file#docker-volumes):
   ```
    docker-volumes: |
    /tmp/wolfi-packages:/tmp/renovate/wolfi-packages
   ```
   If you're using renovate locally, and want to test the datasource, just mount the volume with `--volume /tmp/wolfi-packages:/tmp/renovate/wolfi-packages`

   In the renovate configuration, set a custom manager to update wolfi runtime base packages, pointing the `managerFilePatterns` to where the base image is.
   Keep a loose template because wolfi packages contains distribution-specific revision tag that aren't semver compatible.
   ```
   {
      customType: 'regex',
      managerFilePatterns: ['/^enterprise/images/wolfi/runtime-base/image\\.yaml$/'],
      matchStrings: [
        '-\\s*(?<packageName>[a-zA-Z0-9_.+-]+)=(?<currentValue>[a-zA-Z0-9_.+-]+)'
      ],
      datasourceTemplate: 'custom.wolfi',
      depNameTemplate: '{{packageName}}',
      versioningTemplate: 'loose'
   }
   ```

   Renovate won't have access to files and directories outside of its working directory. That is one of renovate's security design.
   When using the renovate action, the working directory is the repository directory itself, that renovate recreates everytime it runs. This makes the access of our package files impossible.
   To mitigate this, we serve the mounted directory containing the `"package".json` files as an API locally where we're running renovate (in this context, the runner) and setup the datasource accordingly.

   In the renovate entrypoint script :
   ```bash
   python3 -m http.server 8000 --directory /tmp/renovate/wolfi-packages &
   ```
   The datasource properly updated :
   ```
   wolfi: {
      defaultRegistryUrlTemplate: 'http://localhost:8000/{{packageName}}.json',
      transformTemplates: [
        '{"releases": $map($, function($v) { { "version": $v } })}'
      ]
    }
   ```
   For the `transformTemplates` informations you'll find more in https://docs.renovatebot.com/modules/datasource/custom/


## ✅ Requirements

- Python 3.x
- Install dependencies:
  ```bash
  pip install PyYAML requests

