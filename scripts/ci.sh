#!/usr/bin/env bash
# parity-admin-console's local CI (PLAN.md; wave 2: console steps 0, 2, 9 and SAML-PLAN steps 1-4).
# Stops at the first failure.
#   1. tools: Java 21, Maven >= 3.9, docker;
#   2. parity-contracts is the version this build pins (its store schemas and masking cases);
#   3. the realm as code (parity-deploy compose/keycloak/realm-parity.json) and parity-store's jar, both
#      used by the integration tests (the jar is built from a copy under target/ when missing or older
#      than its sources, so parity-store's own tree is never written);
#   4. the test images: postgres and Keycloak 26.8.1 by digest, Redpanda v26.2.3 checked against its digest;
#   5. the shared Error Prone checks (parity-telephony-controller/tools/errorprone-checks);
#   6. mvn verify: the enforcer, javac -Xlint:all -Werror with Error Prone, unit tests, the integration
#      tests on Testcontainers (Postgres, Redpanda, Keycloak with the realm import) and parity-store's
#      jar, all on random ports; the jar, the SBOM, the licence allow-list;
#   3b. the realm file holds no person and no credential, and every placeholder in it resolves from a
#      secret file; the entrypoint fails closed (exit 2) on a missing secret (review MF-1);
#   7. the Keycloak files' syntax (entrypoint, dev-secrets, dev-platform-admin, the spike);
#   8. advisories: OSV-Scanner on the SBOM (needs the network).
#   CI_OFFLINE=1              mvn --offline, the advisory scan skipped (said so)
#   CI_SKIP_CHECKS_INSTALL=1  use the installed Error Prone checks jar
#   PARITY_CONTRACTS_DIR, PARITY_STORE_DIR, PARITY_DEPLOY_DIR   the sibling repositories (defaults: ../)
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONTRACTS=${PARITY_CONTRACTS_DIR:-$ROOT/../parity-contracts}
STORE=${PARITY_STORE_DIR:-$ROOT/../parity-store}
DEPLOY=${PARITY_DEPLOY_DIR:-$ROOT/../parity-deploy}
EXPECTED_CONTRACTS_VERSION=0.17.1
CHECKS=${PARITY_ERRORPRONE_CHECKS:-$ROOT/../parity-telephony-controller/tools/errorprone-checks}
OSV_IMAGE=ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0
POSTGRES_IMAGE=postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
REDPANDA_IMAGE=docker.redpanda.com/redpandadata/redpanda:v26.2.3
REDPANDA_DIGEST=sha256:9e83cfa99278f30d0133271c26bf670cd69c94ffa6ba0b42830dd0c3bd9dcfd9
# Keycloak 26.8.1 (tag 26.8.1-0, published 2026-10-13): the newest 26.x patch at least 14 days old.
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244
step() { printf '== %s\n' "$*"; }
die() { printf 'ci: %s\n' "$*" >&2; exit 3; }
mvn_flags=(-B -ntp -T 2)
if [[ "${CI_OFFLINE:-0}" == 1 ]]; then mvn_flags+=(--offline -Dcyclonedx.skip=true); fi

TEST_LABEL=parity.test=parity-admin-console
cleanup() {
  local ids
  ids=$(docker ps -aq --filter "label=$TEST_LABEL" 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    echo "removing leftover test containers: $(echo $ids | tr '\n' ' ')"
    docker rm -f $ids >/dev/null
  fi
}

step "tools"
java_version=$(java -version 2>&1 | head -1)
[[ "$java_version" == *'"21.'* ]] || die "need Java 21, found: $java_version"
mvn_version=$(mvn -v 2>/dev/null | head -1)
[[ "$mvn_version" =~ Apache\ Maven\ 3\.(9|[1-9][0-9])\. ]] || die "need Maven >= 3.9, found: ${mvn_version:-none}"
command -v docker >/dev/null || die "docker is missing (the integration tests need it)"
docker info >/dev/null 2>&1 || die "docker is not reachable"
echo "$java_version; $mvn_version; $(docker --version)"
cleanup
trap cleanup EXIT

step "parity-contracts $EXPECTED_CONTRACTS_VERSION"
[[ "$(cat "$CONTRACTS/VERSION")" == "$EXPECTED_CONTRACTS_VERSION" ]] \
  || die "parity-contracts is $(cat "$CONTRACTS/VERSION"), parity-admin-console expects $EXPECTED_CONTRACTS_VERSION"
for f in schemas/store/store-requests.v1.json schemas/store/store-replies.v1.json masking/cases.v1.json masking/billing.v1.json; do
  [[ -e "$CONTRACTS/$f" ]] || die "parity-contracts lacks $f"
done
echo "$CONTRACTS"

step "the realm as code and parity-store's jar"
REALM="$DEPLOY/compose/keycloak/realm-parity.json"
[[ -f "$REALM" ]] || die "no realm import at $REALM"
python3 -I -c "import json, sys; r = json.load(open(sys.argv[1])); assert r['realm'] == 'parity' and r['organizationsEnabled']" "$REALM" \
  || die "$REALM isn't the parity realm"
# MF-1: no person and no credential as code (only service accounts), no client secret.
python3 -I - "$REALM" <<'PY' || die "$REALM holds a person, a credential or a secret"
import json, sys
realm = json.load(open(sys.argv[1], encoding="utf-8"))
bad = []
def walk(node, at):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("credentials", "secret"):
                bad.append(at + "/" + k)
            walk(v, at + "/" + k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, at + "/" + str(i))
walk(realm, "")
bad += ["/users/" + u.get("username", "?") for u in realm.get("users", []) if not u.get("serviceAccountClientId")]
for o in realm.get("organizations", []):
    bad += ["/organizations/" + o.get("alias", "?") + "/members" for _ in o.get("members", [])[:1]]
if bad:
    print("ci: not allowed in the realm file: " + ", ".join(bad), file=sys.stderr)
    sys.exit(1)
PY
# The entrypoint's own check (PARITY_KEYCLOAK_CHECK_ONLY): every placeholder resolves from the secret
# files dev-secrets.sh writes (dummy values here), and a missing one, or an unknown placeholder, is exit 2.
KC_ENTRY="$DEPLOY/compose/keycloak/entrypoint.sh"
kc_tmp=$(mktemp -d "${TMPDIR:-/tmp}/acw2-kc-entrypoint.XXXXXX")
mkdir -m 700 "$kc_tmp/secrets" "$kc_tmp/import"
cp "$REALM" "$kc_tmp/import/"
printf 'dummy-not-a-secret' > "$kc_tmp/secrets/admin-password"
kc_check() { PARITY_KEYCLOAK_SECRETS="$kc_tmp/secrets" PARITY_KEYCLOAK_IMPORT_DIR="$kc_tmp/import" \
  PARITY_KEYCLOAK_CHECK_ONLY=1 KC_DB= bash "$KC_ENTRY" >/dev/null 2>&1; }
set +e; kc_check; rc=$?; set -e
[[ $rc == 2 ]] || { rm -rf "$kc_tmp"; die "entrypoint.sh without admin-console-sa.crt.pem: exit $rc, not 2"; }
printf -- '-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n' > "$kc_tmp/secrets/admin-console-sa.crt.pem"
set +e; kc_check; rc=$?; set -e
[[ $rc == 0 ]] || { rm -rf "$kc_tmp"; die "a placeholder in $REALM doesn't resolve from a secret file (entrypoint exit $rc)"; }
printf '{"realm": "planted", "x": "${PARITY_NOT_A_SECRET}"}\n' > "$kc_tmp/import/planted.json"
set +e; kc_check; rc=$?; set -e
rm -rf "$kc_tmp"
[[ $rc == 2 ]] || die "entrypoint.sh with an unknown placeholder: exit $rc, not 2"
echo "realm file: no person, credential or secret; entrypoint fails closed (exit 2) and resolves every placeholder"
STORE_JAR="$STORE/target/parity-store-0.1.0.jar"
if [[ ! -f "$STORE_JAR" ]] || [[ -n "$(find "$STORE/src" "$STORE/pom.xml" -newer "$STORE_JAR" -print -quit)" ]]; then
  echo "parity-store's jar is missing or older than its sources: building a copy under target/"
  rm -rf "$ROOT/target/parity-store-src"
  mkdir -p "$ROOT/target"
  cp -a "$STORE" "$ROOT/target/parity-store-src"
  rm -rf "$ROOT/target/parity-store-src/target"
  mvn "${mvn_flags[@]}" -q -f "$ROOT/target/parity-store-src/pom.xml" -Dparity.contracts.dir="$CONTRACTS" -DskipTests package
  STORE_JAR="$ROOT/target/parity-store-src/target/parity-store-0.1.0.jar"
fi
# parity-rs places new tenants (2026-11-03): its jar, built like parity-store's when stale.
RS=${PARITY_RS_DIR:-$ROOT/../parity-rs}
RS_JAR="$RS/target/parity-rs.jar"
if [[ ! -f "$RS_JAR" ]] || [[ -n "$(find "$RS/src" "$RS/pom.xml" -newer "$RS_JAR" -print -quit)" ]]; then
  echo "parity-rs's jar is missing or older than its sources: building a copy under target/"
  rm -rf "$ROOT/target/parity-rs-src"
  mkdir -p "$ROOT/target"
  cp -a "$RS" "$ROOT/target/parity-rs-src"
  rm -rf "$ROOT/target/parity-rs-src/target"
  mvn "${mvn_flags[@]}" -q -f "$ROOT/target/parity-rs-src/pom.xml" -Dparity.contracts.dir="$CONTRACTS" -DskipTests \
    -Dlicense.skip=true -Dcyclonedx.skip=true package
  RS_JAR="$ROOT/target/parity-rs-src/target/parity-rs.jar"
fi
echo "$REALM; $STORE_JAR; $RS_JAR"

step "test images"
for image in "$POSTGRES_IMAGE" "$REDPANDA_IMAGE" "$KEYCLOAK_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image"
done
digests=$(docker image inspect --format '{{join .RepoDigests " "}}' "$REDPANDA_IMAGE")
[[ " $digests " == *"@$REDPANDA_DIGEST "* ]] || die "$REDPANDA_IMAGE is $digests, not $REDPANDA_DIGEST"
echo "postgres ${POSTGRES_IMAGE#*@}; redpanda v26.2.3 $REDPANDA_DIGEST; keycloak 26.8.1 ${KEYCLOAK_IMAGE#*@}"

step "Error Prone checks (NoDataInMessages, NoSynchronized)"
if [[ "${CI_SKIP_CHECKS_INSTALL:-0}" == 1 ]]; then
  ls ~/.m2/repository/parity/parity-errorprone-checks/0.1.0/parity-errorprone-checks-0.1.0.jar >/dev/null \
    || die "CI_SKIP_CHECKS_INSTALL=1 but the checks jar isn't installed"
  echo "using the installed checks jar"
else
  mvn "${mvn_flags[@]}" -q -f "$CHECKS/pom.xml" install
fi

step "mvn verify"
rm -rf "$ROOT/target/failsafe-reports" "$ROOT/target/surefire-reports" # the log check reads this run's captures only
cd "$ROOT"
mvn "${mvn_flags[@]}" -Dparity.contracts.dir="$CONTRACTS" -Dparity.realm.file="$REALM" -Dparity.store.jar="$STORE_JAR" -Dparity.rs.jar="$RS_JAR" verify

step "logs (log-record.v1, logging/events.parity-admin-console.v1.json)"
CHECK="$CONTRACTS/rust/target/debug/contract-check"
[[ -x "$CHECK" ]] || die "contract-check isn't built (run parity-contracts' scripts/ci.sh)"
log_args=()
for c in target/failsafe-reports/*-output.txt target/surefire-reports/*-output.txt; do
  [[ -f "$c" ]] && log_args+=(--logs "$c")
done
(( ${#log_args[@]} )) || die "no test log capture"
"$CHECK" --root "$CONTRACTS" --catalogue logging/events.parity-admin-console.v1.json "${log_args[@]}" --skip-non-json

step "Keycloak files (parity-deploy compose/keycloak)"
bash -n "$DEPLOY/compose/keycloak/entrypoint.sh" || die "entrypoint.sh doesn't parse"
sh -n "$DEPLOY/compose/keycloak/dev-secrets.sh" || die "dev-secrets.sh doesn't parse"
for p in "$DEPLOY/compose/keycloak/spike/spike.py" "$DEPLOY/compose/keycloak/spike/kc.py" "$DEPLOY/compose/keycloak/dev-platform-admin.py"; do
  python3 -I -c "import ast, sys; ast.parse(open(sys.argv[1]).read())" "$p" || die "$p doesn't parse"
done
for j in "$DEPLOY"/compose/keycloak/spike/realm-*.json; do
  python3 -I -c "import json, sys; json.load(open(sys.argv[1]))" "$j" || die "$j isn't JSON"
done

step "advisories (OSV-Scanner on target/bom.json)"
if [[ "${CI_OFFLINE:-0}" == 1 ]]; then
  echo "SKIPPED: CI_OFFLINE=1 (OSV-Scanner needs osv.dev)"
else
  [[ -f target/bom.json ]] || die "no SBOM at target/bom.json"
  docker run --rm --network bridge --security-opt label=disable --read-only --cap-drop ALL \
    -v "$ROOT/target/bom.json:/src/bom.json:ro" -v "$ROOT/osv-scanner.toml:/src/osv-scanner.toml:ro" \
    "$OSV_IMAGE" scan source --config /src/osv-scanner.toml -L /src/bom.json
fi

step "parity-admin-console ok"
