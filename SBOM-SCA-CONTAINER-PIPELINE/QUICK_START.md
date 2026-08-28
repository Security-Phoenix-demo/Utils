# sbom-single-repo — Quick Start

## 1) Move to utility folder and install dependencies

```bash
# from repository root
cd Utils/sca-pipeline/sbom-single-repo
python3 -m pip install -r requirements.txt
```

## 2) Configure Phoenix credentials

Precedence: CLI flags > environment variables > `config.ini`.

Option A - environment variables (recommended for CI):

```bash
export PHOENIX_CLIENT_ID="<your-client-id>"
export PHOENIX_CLIENT_SECRET="<your-client-secret>"
export PHOENIX_API_BASE_URL="https://api.securityphoenix.cloud"
```

Option B - local config file (never commit it):

```bash
cp config.ini.template config.ini
chmod 600 config.ini
# edit config.ini with your values
```

Option C - Jenkins: add `phoenix-client-id` and `phoenix-client-secret` as **Secret text**
credentials. `jenkins_sbom_single_repo_pipeline.groovy` binds them for you.

## 3) Generate the SBOM

`--scanners vuln` is required for `--method vulnerability` - without it the SBOM has no
vulnerabilities and Phoenix receives zero findings. For `--method sbom` leave it off: Phoenix
runs dep-scan over the uploaded SBOM and derives the vulnerabilities itself.

```bash
# container image (needs the Docker socket)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/workspace" \
  aquasec/trivy:latest image --scanners vuln --format cyclonedx \
    --output /workspace/sbom.cdx.json myregistry.io/payments-api:1.4.2

# repository build files (no Docker socket needed)
docker run --rm -v "$PWD:/workspace" \
  aquasec/trivy:latest fs --scanners vuln --format cyclonedx \
    --output /workspace/sbom.cdx.json /workspace
```

With Trivy installed locally, drop the `docker run` wrapper:
`trivy image --scanners vuln --format cyclonedx --output sbom.cdx.json <image>`.

## 4) Run import

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --import-type merge
```

## 5) Dry-run and payload preview (recommended first run)

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --dry-run \
  --payload-out payload-preview.json
```

## 6) Bitbucket Pipelines mode

If running in Bitbucket Pipelines, use:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-bitbucket-env \
  --import-type merge
```

You can still override any value manually (for example `--repo` or `--branch`).

## 7) Jenkins mode

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-jenkins-env \
  --import-type merge
```

Picks up `GIT_URL`, `BRANCH_NAME`/`GIT_BRANCH`, `GIT_COMMIT`, `BUILD_NUMBER`, and `BUILD_URL`.
Or use the ready-made `jenkins_sbom_single_repo_pipeline.groovy` and set `SCAN_MODE` to
`buildfile` or `image`.

## 8) Quick repo navigation commands

```bash
# return to the repository root
cd ..

# inspect the available utilities
/bin/ls -a
```

## 9) Where to go next

- `./README.md` - the full reference: every option, both import methods, all three scanners,
  and the Jenkins, GitHub Actions and Bitbucket pipelines
- `../README.md` - the other utilities in this repository and what each is for

## Notes

- Asset identity is sent as `buildFile=repo/file:branch`
- Findings are imported from CycloneDX `vulnerabilities[]`
- Components are attached as `installedSoftware[]`
- Severity is the highest rating across all CycloneDX sources (ghsa, nvd, redhat, ...), not the first one listed
- For `--method vulnerability`, generate the SBOM with `--scanners vuln`, otherwise Trivy emits components only and no findings are imported (`--method sbom` wants the inventory-only SBOM instead):
  - build files: `trivy fs --scanners vuln --format cyclonedx --output sbom.cdx.json .`
  - container image: `trivy image --scanners vuln --format cyclonedx --output sbom.cdx.json <image>`
- In Jenkins use `--from-jenkins-env` to pick up repo, branch, commit, build number, and build URL
