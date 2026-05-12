#!/usr/bin/env bash
# Sprint B0 — turnkey EC2 bootstrap for benchmark host.
#
# Brings a fresh Ubuntu 22.04 m6id.xlarge instance to a state where you can
# run cmd/seed and cmd/bench against a local Postgres on the instance-store
# NVMe. The NVMe is critical: Postgres on EBS introduces tail-latency noise
# that pollutes the percentile metrics the paper reports.
#
# Provision the instance first (run locally, not on the instance):
#
#   aws ec2 run-instances \
#     --instance-type m6id.xlarge \
#     --image-id ami-0a628e1e89aaedf80          \   # Ubuntu 22.04 eu-central-1
#     --count 1 \
#     --key-name your-keypair \
#     --region eu-central-1 \
#     --security-group-ids sg-XXXXXX \
#     --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=tdsc-bench}]'
#
# Then SSH in and run this script:
#
#   scp scripts/ec2-bootstrap.sh ubuntu@<ip>:~/
#   ssh ubuntu@<ip> 'bash ~/ec2-bootstrap.sh'
#
# After it finishes, the ATL service is built at /data/atl/bin/atl-service
# and Postgres is running on the NVMe. Next steps printed at the end.
set -euo pipefail

GO_VERSION="1.23.0"
ATL_REPO="${ATL_REPO:-https://github.com/Epsilon-Data/epsilon-atl.git}"
ATL_BRANCH="${ATL_BRANCH:-main}"

log() { printf '\033[36m[bootstrap]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. Mount instance-store NVMe at /data
# ---------------------------------------------------------------------------
if [ ! -d /data ] || ! mountpoint -q /data; then
    log "Mounting NVMe at /data"
    NVME=$(lsblk -dno NAME,TYPE,MOUNTPOINT | awk '$2=="disk" && $3=="" && $1 ~ /^nvme/ {print "/dev/"$1; exit}')
    if [ -z "${NVME}" ]; then
        log "ERROR: no unmounted NVMe device found. Available block devices:"
        lsblk
        exit 1
    fi
    log "  using ${NVME}"
    sudo mkfs.ext4 -F "${NVME}"
    sudo mkdir -p /data
    sudo mount "${NVME}" /data
    sudo chown "$USER:$USER" /data
fi

# ---------------------------------------------------------------------------
# 2. System packages
# ---------------------------------------------------------------------------
log "Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y -qq postgresql postgresql-client jq htop iotop git

# ---------------------------------------------------------------------------
# 3. Go toolchain
# ---------------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
    log "Installing Go ${GO_VERSION}"
    cd /tmp
    curl -sLO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    export PATH=$PATH:/usr/local/go/bin
fi
go version

# ---------------------------------------------------------------------------
# 4. Postgres → /data
# ---------------------------------------------------------------------------
PG_DATA_DEFAULT=$(sudo -u postgres psql -t -c "SHOW data_directory" | tr -d ' ')
if [[ "${PG_DATA_DEFAULT}" != /data/* ]]; then
    log "Moving Postgres data dir from ${PG_DATA_DEFAULT} to /data"
    sudo systemctl stop postgresql
    sudo cp -a "${PG_DATA_DEFAULT}" /data/postgresql
    PG_CONF=$(sudo find /etc/postgresql -name postgresql.conf | head -1)
    sudo sed -i "s|^data_directory.*|data_directory = '/data/postgresql'|" "${PG_CONF}"
    sudo systemctl start postgresql
fi
sudo systemctl status postgresql --no-pager | head -5 || true

# ---------------------------------------------------------------------------
# 5. Create the atl databases (one per scale point for B1)
# ---------------------------------------------------------------------------
log "Creating Postgres user + databases (one per scale: 1e3 .. 1e7)"
sudo -u postgres psql <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'atl') THEN
        CREATE USER atl WITH SUPERUSER PASSWORD 'atl';
    END IF;
END
\$\$;
SQL
for scale in 1000 10000 100000 1000000 10000000; do
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='atl_${scale}'" | grep -q 1 \
        || sudo -u postgres createdb -O atl "atl_${scale}"
done

# ---------------------------------------------------------------------------
# 6. Clone and build epsilon-atl
# ---------------------------------------------------------------------------
if [ ! -d /data/atl ]; then
    log "Cloning ${ATL_REPO} (branch ${ATL_BRANCH}) into /data/atl"
    git clone --branch "${ATL_BRANCH}" "${ATL_REPO}" /data/atl
fi
cd /data/atl
log "Building atl-service + bench tools"
mkdir -p bin
go build -o bin/atl-service ./cmd/atl
go build -o bin/seed ./cmd/seed
go build -o bin/bench ./cmd/bench
go build -o bin/bench-scale ./cmd/bench-scale
go build -o bin/bench-compare ./cmd/bench-compare
ls -lh bin/

# ---------------------------------------------------------------------------
# 7. Generate Ed25519 keys (operator STH key + coordinator-bench key)
# ---------------------------------------------------------------------------
KEYDIR=/data/atl/keys
mkdir -p "${KEYDIR}"
chmod 700 "${KEYDIR}"
if [ ! -f "${KEYDIR}/operator.key" ]; then
    log "Generating operator STH signing key"
    openssl genpkey -algorithm ED25519 -out "${KEYDIR}/operator.key"
fi
if [ ! -f "${KEYDIR}/coordinator-bench.key" ]; then
    log "Generating coordinator-bench signing key"
    openssl genpkey -algorithm ED25519 -out "${KEYDIR}/coordinator-bench.key"
fi
chmod 600 "${KEYDIR}"/*.key

# ---------------------------------------------------------------------------
# Done. Print next steps.
# ---------------------------------------------------------------------------
cat <<EOF

  ====================================================================
  EC2 bench host is ready.
  ====================================================================

  Paths:
    ATL binaries:  /data/atl/bin/
    Postgres data: /data/postgresql/
    Keys:          /data/atl/keys/

  Databases created (one per benchmark scale):
    atl_1000, atl_10000, atl_100000, atl_1000000, atl_10000000

  Next: B1 — pre-populate each scale (run in tmux/screen).
  Recommended order: smallest first so you can sanity-check fast.

    cd /data/atl
    export ATL_OPERATOR_KEY_PATH=\${PWD}/keys/operator.key
    export ATL_COORDINATOR_KEY_PATH=\${PWD}/keys/coordinator-bench.key

    # 1e3
    ATL_DATABASE_URL=postgres://atl:atl@localhost/atl_1000?sslmode=disable \\
      ./bin/seed --type=mixed --count=1000

    # 1e4
    ATL_DATABASE_URL=postgres://atl:atl@localhost/atl_10000?sslmode=disable \\
      ./bin/seed --type=mixed --count=10000

    # ...continue through 1e7 (run overnight in tmux for 1e7)
    # Expect ~7ms/entry → 1e6 ~2h, 1e7 ~19h.

  After B1 completes, run B2/B3/B4 against the populated logs.

EOF
