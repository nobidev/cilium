import tarfile
import gzip
import io
import re
import sys
import yaml
import requests
import os
import json

def main(yaml_path):
    with open(yaml_path) as f:
        packages = yaml.safe_load(f)

    os.makedirs("/tmp/wolfi-packages/", exist_ok=True)
    data = fetch_and_parse_apkindex()

    for entry in packages.get("contents", {}).get("packages", []):
        match = re.match(r'^\s*([^=#\s]+)*', entry)
        if match:
            pkg_name = match.group(1)
            print(pkg_name)
            with open(f"/tmp/wolfi-packages/{pkg_name}.json", "w") as out_file: out_file.write(str(json.dumps(data.get(pkg_name))))


def fetch_and_parse_apkindex():
    url = "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz"
    response = requests.get(url)
    response.raise_for_status()

    with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
        with tarfile.open(fileobj=gz, mode="r:") as tar:
            apkindex_file = tar.extractfile("APKINDEX")
            if not apkindex_file:
                raise ValueError("APKINDEX not found in tarball")

            content = apkindex_file.read().decode("utf-8")
            return parse_apkindex(content)

def parse_apkindex(content):
    versions_by_name = {}
    current_pkg = {}

    for line in content.splitlines():
        if not line:
            continue

        tag = line[0]
        value = line[1:].strip()
        current_pkg[tag] = value

        if  all(k in current_pkg for k in ("P", "V")):
            name = current_pkg["P"].lstrip(":")
            version = current_pkg["V"].lstrip(":")
            versions_by_name.setdefault(name, []).append(version)
            current_pkg = {}

    return versions_by_name

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wolfi_packages.py <path-to-wolfi-image-file>")
        sys.exit(1)

    yaml_file_path = sys.argv[1]
    main(yaml_file_path)