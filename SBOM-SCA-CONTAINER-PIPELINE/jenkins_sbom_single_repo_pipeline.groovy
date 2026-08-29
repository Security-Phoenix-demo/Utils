// Single-repo SBOM -> Phoenix.
//
// Three independent choices.
//
// PHOENIX_METHOD - which Phoenix API the result is sent to:
//   sbom          POST /v1/import/assets/file/translate, scanType "PhxSbomSca:<projectType>".
//                 Uploads a plain inventory SBOM; Phoenix runs its own dep-scan service over it
//                 to derive vulnerabilities, then translates and imports. The pipeline does no
//                 vulnerability analysis.
//   vulnerability POST /v1/import/assets. The pipeline scans for vulnerabilities and posts the
//                 findings as JSON. The SBOM must already contain vulnerabilities.
//   auto          buildfile -> sbom, image -> vulnerability. This is the default.
//
// SCAN_MODE - what gets scanned:
//   buildfile     dependency manifests in the workspace. Requires the repo to be checked out,
//                 so use a "Pipeline script from SCM" job.
//   image         a container image. Requires access to the Docker socket.
//
// SCANNER - which tool produces the SBOM:
//   cdxgen        inventory SBOM only, no vulnerability analysis. For PHOENIX_METHOD=sbom.
//   trivy         CycloneDX with vulnerabilities (--scanners vuln). For PHOENIX_METHOD=vulnerability.
//   depscan       OWASP dep-scan VDR. For PHOENIX_METHOD=vulnerability. Needs a cached
//                 vulnerability DB (DEPSCAN_VDB_VOLUME) or every build re-downloads ~4GB.
//   auto          sbom -> cdxgen, vulnerability -> trivy. This is the default.
//
// Repository/branch/commit/build metadata is read from the Jenkins environment via
// --from-jenkins-env. Leave REPO_NAME and BRANCH blank to use the values Jenkins exports after
// checkout (GIT_URL, BRANCH_NAME/GIT_BRANCH), or set them to override.

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    parameters {
        choice(name: 'PHOENIX_METHOD', choices: ['auto', 'sbom', 'vulnerability'], description: 'Which Phoenix import API to use. auto = sbom for build files, vulnerability for images')
        choice(name: 'SCAN_MODE', choices: ['buildfile', 'image'], description: 'Scan workspace build files (SCA) or a container image')
        choice(name: 'SCANNER', choices: ['auto', 'cdxgen', 'trivy', 'depscan'], description: 'SBOM producer. auto = cdxgen for the sbom method, trivy for the vulnerability method')
        string(name: 'SCAN_PATH', defaultValue: '.', description: 'buildfile mode: path within the workspace to scan')
        string(name: 'CONTAINER_IMAGE', defaultValue: 'nginx:latest', description: 'image mode: image to scan')
        string(name: 'PROJECT_TYPE', defaultValue: 'universal', description: 'Project type for cdxgen -t and for the Phoenix scanType PhxSbomSca:<projectType> (universal, js, python, java, go, ...)')
        string(name: 'REPO_NAME', defaultValue: '', description: 'Repository identifier (blank = derive from Jenkins GIT_URL)')
        string(name: 'FILE_PATH', defaultValue: 'package-lock.json', description: 'Repository file/manifest path (image mode: use e.g. Dockerfile)')
        string(name: 'BRANCH', defaultValue: '', description: 'Branch name (blank = derive from Jenkins BRANCH_NAME/GIT_BRANCH)')
        choice(name: 'PHOENIX_IMPORT_TYPE', choices: ['merge', 'new', 'delta'], description: 'Phoenix import type. merge keeps findings this scan did not see; delta closes them')
        booleanParam(name: 'WAIT_FOR_COMPLETION', defaultValue: false, description: 'sbom method: hold the build until Phoenix finishes translating and importing. Successful imports measured 4-5 minutes; a request still translating well past that has usually collided with another upload and ends in ERROR near 60 minutes, so waiting mostly occupies an executor. Leave it off unless a later stage depends on the import having landed; the upload is confirmed and the request id printed either way')
        string(name: 'PHOENIX_API_BASE_URL', defaultValue: 'https://api.securityphoenix.cloud', description: 'Phoenix API URL')
        string(name: 'TRIVY_IMAGE', defaultValue: 'aquasec/trivy:0.74.0', description: 'Trivy scanner image. Pinned rather than latest so a moved tag cannot change what a build scans with')
        string(name: 'DEPSCAN_IMAGE', defaultValue: 'ghcr.io/owasp-dep-scan/dep-scan@sha256:c305f241a3c2e35a90472ef7cb971b03904f719a6b736ab40b4a0039ce8470c4', description: 'OWASP dep-scan image (also provides cdxgen), pinned by digest. Its vulnerability database format is tied to the dep-scan version, so a moved tag can invalidate a warmed VDB volume')
        string(name: 'DEPSCAN_VDB_VOLUME', defaultValue: 'depscan-vdb', description: 'Docker volume caching the dep-scan vulnerability DB (~4GB). Without it every build re-downloads it')
    }

    environment {
        PHOENIX_CLIENT_ID = credentials('phoenix-client-id')
        PHOENIX_CLIENT_SECRET = credentials('phoenix-client-secret')
        SBOM_FILE = "${WORKSPACE}/sbom.cdx.json"
        // Kept inside the workspace on purpose. The scanner containers receive this path
        // through "docker run -v", and the Docker daemon resolves bind-mount sources on the
        // host - not inside whatever container issued the command. When Jenkins itself runs
        // in a container, a /tmp path therefore names the host's /tmp while the agent reads
        // its own, and the scan output silently lands somewhere the build cannot see. The
        // workspace is the one directory that must already be mount-visible for the scanners
        // to read the source at all, so putting reports there keeps both sides in agreement.
        SCAN_REPORTS = "${WORKSPACE}/.phoenix-sbom-reports"
    }

    stages {
        stage('Resolve method and scanner') {
            steps {
                script {
                    // Parameters are only injected into the shell environment for builds that
                    // were given parameter values. A job's very first build registers the
                    // definitions but runs without them, so every `sh` block below would see an
                    // unset variable and abort under `set -u`. Binding them to env here makes the
                    // first build behave like every later one.
                    env.SCAN_PATH = params.SCAN_PATH
                    env.CONTAINER_IMAGE = params.CONTAINER_IMAGE
                    env.PROJECT_TYPE = params.PROJECT_TYPE
                    env.REPO_NAME = params.REPO_NAME
                    env.FILE_PATH = params.FILE_PATH
                    env.BRANCH = params.BRANCH
                    env.PHOENIX_IMPORT_TYPE = params.PHOENIX_IMPORT_TYPE
                    env.PHOENIX_API_BASE_URL = params.PHOENIX_API_BASE_URL
                    env.TRIVY_IMAGE = params.TRIVY_IMAGE
                    env.DEPSCAN_IMAGE = params.DEPSCAN_IMAGE
                    env.DEPSCAN_VDB_VOLUME = params.DEPSCAN_VDB_VOLUME
                    env.WAIT_FOR_COMPLETION = params.WAIT_FOR_COMPLETION ? 'true' : 'false'

                    // auto: an explicit scanner choice already implies the method - cdxgen only
                    // produces an inventory SBOM, while trivy and dep-scan exist to find
                    // vulnerabilities. Only when the scanner is also 'auto' does the scan mode
                    // decide: build files carry no vulnerability data of their own so they go to
                    // Phoenix for analysis, whereas an image is scanned here and the findings sent.
                    if (params.PHOENIX_METHOD != 'auto') {
                        env.EFFECTIVE_METHOD = params.PHOENIX_METHOD
                    } else if (params.SCANNER == 'cdxgen') {
                        env.EFFECTIVE_METHOD = 'sbom'
                    } else if (params.SCANNER == 'trivy' || params.SCANNER == 'depscan') {
                        env.EFFECTIVE_METHOD = 'vulnerability'
                    } else {
                        env.EFFECTIVE_METHOD = params.SCAN_MODE == 'buildfile' ? 'sbom' : 'vulnerability'
                    }

                    // cdxgen cannot export a container image from inside its own container -
                    // it reports "Unable to pull <image>" even when the image is local - so an
                    // image-mode inventory SBOM comes from Trivy with the vulnerability scanners
                    // switched off instead.
                    if (params.SCANNER != 'auto') {
                        env.EFFECTIVE_SCANNER = params.SCANNER
                    } else if (env.EFFECTIVE_METHOD == 'sbom') {
                        env.EFFECTIVE_SCANNER = params.SCAN_MODE == 'image' ? 'trivy' : 'cdxgen'
                    } else {
                        env.EFFECTIVE_SCANNER = 'trivy'
                    }

                    if (env.EFFECTIVE_METHOD == 'vulnerability' && env.EFFECTIVE_SCANNER == 'cdxgen') {
                        error("SCANNER=cdxgen produces an inventory SBOM with no vulnerabilities, " +
                              "so PHOENIX_METHOD=vulnerability would import zero findings. " +
                              "Use SCANNER=trivy or SCANNER=depscan, or switch to PHOENIX_METHOD=sbom.")
                    }
                    if (env.EFFECTIVE_SCANNER == 'cdxgen' && params.SCAN_MODE == 'image') {
                        error("SCANNER=cdxgen cannot build an SBOM from a container image: it runs " +
                              "inside its own container and cannot export the image through the " +
                              "mounted Docker socket. Use SCANNER=trivy (or leave SCANNER=auto) " +
                              "for image mode.")
                    }
                    if (env.EFFECTIVE_METHOD == 'sbom' && env.EFFECTIVE_SCANNER == 'depscan') {
                        error("SCANNER=depscan runs the vulnerability analysis that Phoenix would " +
                              "run again for PHOENIX_METHOD=sbom. Use SCANNER=cdxgen for the sbom " +
                              "method, or switch to PHOENIX_METHOD=vulnerability.")
                    }

                    echo "method=${env.EFFECTIVE_METHOD} scanner=${env.EFFECTIVE_SCANNER} mode=${params.SCAN_MODE}"
                }
            }
        }

        stage('Generate SBOM') {
            steps {
                sh '''#!/usr/bin/env bash
                    set -euo pipefail
                    rm -rf "$SCAN_REPORTS"
                    mkdir -p "$SCAN_REPORTS"
                    chmod 777 "$SCAN_REPORTS"
                '''
                script {
                    if (env.EFFECTIVE_SCANNER == 'cdxgen') {
                        // Build files only - image mode is rejected during resolution because
                        // cdxgen cannot export an image from inside its own container.
                        // cdxgen also refuses to run with root privileges, so it uses the
                        // image's default user and a world-writable reports dir.
                        sh '''#!/usr/bin/env bash
                    set -euo pipefail
                            docker run --rm \
                                -v "$WORKSPACE:/app:ro" \
                                -v "$SCAN_REPORTS:/reports:rw" \
                                --entrypoint cdxgen "$DEPSCAN_IMAGE" \
                                -t "$PROJECT_TYPE" -o /reports/sbom.cdx.json "/app/$SCAN_PATH"
                            cp "$SCAN_REPORTS/sbom.cdx.json" "$SBOM_FILE"
                        '''

                    } else if (env.EFFECTIVE_SCANNER == 'depscan') {
                        // dep-scan needs a ~3.7GB (app) / ~4.4GB (app+os) vulnerability database.
                        // It is a single streamed download that fails outright on a dropped
                        // connection, so a cold agent is warned here rather than discovering it
                        // half way through a build. depscan_vdb_warm.sh populates the volume.
                        sh '''#!/usr/bin/env bash
                    set -euo pipefail
                            docker volume create "$DEPSCAN_VDB_VOLUME" >/dev/null
                            # Measure the extracted database only. A failed download leaves its
                            # partial archive (data.vdb*.tar.xz, several GB) behind, so summing the
                            # whole volume reports a cold agent as warm and the build then starts
                            # the multi-GB download this check exists to warn about.
                            vdb_bytes=$(docker run --rm -v "$DEPSCAN_VDB_VOLUME:/vdb" alpine sh -c '
                                total=0
                                for f in /vdb/data.vdb*; do
                                    case "$f" in *.tar.*) continue ;; esac
                                    [ -f "$f" ] || continue
                                    total=$((total + $(stat -c %s "$f" 2>/dev/null || echo 0)))
                                done
                                echo "$total"' 2>/dev/null || echo 0)
                            if [ "${vdb_bytes:-0}" -lt 1000000000 ]; then
                                echo "WARNING: $DEPSCAN_VDB_VOLUME holds only ${vdb_bytes:-0} bytes of extracted database." >&2
                                echo "WARNING: dep-scan will download the full vulnerability database during this build," >&2
                                echo "WARNING: which is slow and fails on any connection drop. Warm it first with:" >&2
                                echo "WARNING:   Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo/depscan_vdb_warm.sh app" >&2
                            else
                                echo "dep-scan VDB cache present (${vdb_bytes} bytes)"
                            fi
                        '''
                        if (params.SCAN_MODE == 'image') {
                            sh '''#!/usr/bin/env bash
                    set -euo pipefail
                                docker run --rm -u root \
                                    -v "$DEPSCAN_VDB_VOLUME:/vdb" -e VDB_HOME=/vdb \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$SCAN_REPORTS:/reports:rw" \
                                    "$DEPSCAN_IMAGE" \
                                    depscan --no-banner --vdb-scope app+os \
                                        --src "$CONTAINER_IMAGE" --reports-dir /reports
                            '''
                        } else {
                            sh '''#!/usr/bin/env bash
                    set -euo pipefail
                                docker run --rm -u root \
                                    -v "$DEPSCAN_VDB_VOLUME:/vdb" -e VDB_HOME=/vdb \
                                    -v "$WORKSPACE:/app:ro" \
                                    -v "$SCAN_REPORTS:/reports:rw" \
                                    "$DEPSCAN_IMAGE" \
                                    depscan --no-banner --vdb-scope app \
                                        --src "/app/$SCAN_PATH" --reports-dir /reports
                            '''
                        }
                        // dep-scan names the VDR sbom-<project_type>.vdr.json, so it is located by glob.
                        sh '''#!/usr/bin/env bash
                    set -euo pipefail
                            vdr=$(ls -1 "$SCAN_REPORTS"/*.vdr.json 2>/dev/null | head -1)
                            if [ -z "$vdr" ]; then
                                echo "dep-scan produced no .vdr.json under $SCAN_REPORTS" >&2
                                ls -la "$SCAN_REPORTS" >&2 || true
                                exit 1
                            fi
                            echo "Using dep-scan VDR: $vdr"
                            cp "$vdr" "$SBOM_FILE"
                        '''

                    } else {
                        // For the vulnerability method --scanners vuln is required: without it Trivy
                        // emits an inventory-only SBOM with an empty "vulnerabilities" array and
                        // Phoenix receives 0 findings. For the sbom method Phoenix does the analysis,
                        // so the flag is omitted rather than scanning and discarding the result.
                        if (params.SCAN_MODE == 'image') {
                            sh '''#!/usr/bin/env bash
                    set -euo pipefail
                                # Derived here rather than passed in as an env var: Jenkins drops
                                # environment variables whose value is the empty string, so the
                                # inventory-SBOM case would arrive unset and trip `set -u`.
                                scanners=""
                                if [ "$EFFECTIVE_METHOD" = "vulnerability" ]; then
                                    scanners="--scanners vuln"
                                fi
                                docker run --rm \
                                    -v /var/run/docker.sock:/var/run/docker.sock \
                                    -v "$WORKSPACE:/workspace" \
                                    "$TRIVY_IMAGE" image \
                                    $scanners --format cyclonedx \
                                    --output /workspace/sbom.cdx.json "$CONTAINER_IMAGE"
                            '''
                        } else {
                            sh '''#!/usr/bin/env bash
                    set -euo pipefail
                                scanners=""
                                if [ "$EFFECTIVE_METHOD" = "vulnerability" ]; then
                                    scanners="--scanners vuln"
                                fi
                                docker run --rm \
                                    -v "$WORKSPACE:/workspace" \
                                    "$TRIVY_IMAGE" fs \
                                    $scanners --format cyclonedx \
                                    --output /workspace/sbom.cdx.json "/workspace/$SCAN_PATH"
                            '''
                        }
                    }
                }
            }
        }

        stage('Send to Phoenix') {
            steps {
                sh '''#!/usr/bin/env bash
                    set -euo pipefail
                    cd "Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo"

                    # The importer needs `requests`. Agents differ: some already have it, and a
                    # modern Debian/Ubuntu python refuses a plain `pip install` outright with
                    # "externally-managed-environment" (PEP 668). Use what is already installed,
                    # fall back to a workspace venv, and only then to a user-level install.
                    # The venv deliberately lives outside the workspace. It survives between
                    # builds, and anything left in the workspace is scanned by the next build -
                    # a venv's site-packages would show up as components of the application.
                    # WORKSPACE_TMP is Jenkins' per-workspace temp directory, a sibling of the
                    # workspace rather than a child of it.
                    VENV="${WORKSPACE_TMP:-/tmp}/phoenix-importer-venv"
                    PY=python3
                    if ! python3 -c "import requests" >/dev/null 2>&1; then
                        if python3 -m venv "$VENV" >/dev/null 2>&1; then
                            PY="$VENV/bin/python"
                            "$PY" -m pip install --quiet -r requirements.txt
                        else
                            python3 -m pip install --quiet --user -r requirements.txt
                        fi
                    fi
                    "$PY" -c "import requests" || {
                        echo "Cannot import requests. Install it on the agent, or make python3-venv available." >&2
                        exit 1
                    }

                    export PHOENIX_CLIENT_ID="$PHOENIX_CLIENT_ID"
                    export PHOENIX_CLIENT_SECRET="$PHOENIX_CLIENT_SECRET"
                    export PHOENIX_API_BASE_URL="$PHOENIX_API_BASE_URL"

                    wait_flag=""
                    if [ "$EFFECTIVE_METHOD" = "sbom" ] && [ "$WAIT_FOR_COMPLETION" = "true" ]; then
                        wait_flag="--wait"
                    fi

                    "$PY" sbom_sca_single_repo_to_phoenix.py \
                        --sbom-file "$SBOM_FILE" \
                        ${REPO_NAME:+--repo "$REPO_NAME"} \
                        --file-path "$FILE_PATH" \
                        ${BRANCH:+--branch "$BRANCH"} \
                        --import-type "$PHOENIX_IMPORT_TYPE" \
                        --method "$EFFECTIVE_METHOD" \
                        --project-type "$PROJECT_TYPE" \
                        $wait_flag \
                        --from-jenkins-env
                '''
            }
        }
    }

    post {
        always {
            // Archived before the cleanup below removes it. When an import fails the SBOM is
            // the evidence needed to tell a scanner problem from an API one, and it is gone
            // from the workspace by the time anyone reads the build.
            archiveArtifacts artifacts: 'sbom.cdx.json', allowEmptyArchive: true, fingerprint: true
            sh 'rm -f "$SBOM_FILE"; rm -rf "$SCAN_REPORTS"'
        }
    }
}
