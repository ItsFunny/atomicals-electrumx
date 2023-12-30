rm -rf a.log
killall electrumx_server
rm -rf data && mkdir data
set -a
source .env
set +a
python3 electrumx_server  > a.log 2>&1 &
