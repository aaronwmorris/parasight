#!/bin/bash


NICENESS=19
APP_ENV=$1
QUEUES=$2
MAX_WORKERS=$3

NOTIFY=0  # Enabled later
NOTIFY_EMAIL="celery@example.com"
EMAIL_FROM="celery@parasight.local"


if [ -z "$QUEUES" ]; then {
    LOCAL_QUEUE=$(hostname -s)
    QUEUES="celery,${LOCAL_QUEUE}" #all queues for dev/test
} fi

if [ -z "$MAX_WORKERS" ]; then {
    MAX_WORKERS=15
} fi



NODENAME="$(hostname)-${RANDOM}"

echo "Starting workers in 5 seconds"
echo "Node: ${NODENAME}"
echo "Queues: ${QUEUES}"
sleep 5




case "$APP_ENV" in
    prod*)
        echo "Environment: production"
        LOG_LEVEL="WARNING"
        BEAT_OPT="" #Beat is a separate process in production
        NOTIFY=1  # Notifications only in prod
        ;;
    *)
        echo "Environment: dev/test"
        LOG_LEVEL="INFO"
        MAX_WORKERS=5
        BEAT_OPT="-B"
        ###NOTIFY=1
        ;;
esac



nice -n ${NICENESS} celery -A mysite worker ${BEAT_OPT} -Q ${QUEUES} -n ${NODENAME} -l ${LOG_LEVEL} -Ofair --concurrency=${MAX_WORKERS}


# send alert
if [ $NOTIFY == 1 ]; then {
    echo "Sending alert"
    mail -s "Celery queue down" -r "${EMAIL_FROM}" $NOTIFY_EMAIL <<EOF
Parasight queue ${QUEUES} has stopped

EOF

} fi

