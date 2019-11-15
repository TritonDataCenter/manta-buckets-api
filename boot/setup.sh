#!/bin/bash
# -*- mode: shell-script; fill-column: 80; -*-
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2019 Joyent, Inc.
#

set -o xtrace

SOURCE="${BASH_SOURCE[0]}"
if [[ -h $SOURCE ]]; then
    SOURCE="$(readlink "$SOURCE")"
fi
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
PROFILE=/root/.bashrc
SVC_ROOT=/opt/smartdc/buckets-api

source ${DIR}/scripts/util.sh
source ${DIR}/scripts/services.sh


export PATH=$SVC_ROOT/build/node/bin:$SVC_ROOT/node_modules/.bin:/opt/local/bin:/usr/sbin:/usr/bin:$PATH


function wait_for_resolv_conf {
    local attempt=0
    local isok=0
    local num_ns

    while [[ $attempt -lt 30 ]]
    do
        num_ns=$(grep nameserver /etc/resolv.conf | wc -l)
        if [ $num_ns -gt 1 ]
        then
            isok=1
            break
        fi
        let attempt=attempt+1
        sleep 1
    done
    [[ $isok -eq 1 ]] || fatal "manatee is not up"
}


function manta_setup_buckets_api {
    local num_instances=1
    local size=`json -f ${METADATA} SIZE`
    if [ "$size" = "lab" ]
    then
        num_instances=4
    elif [ "$size" = "production" ]
    then
        num_instances=16
    fi

    #Build the list of ports.  That'll be used for everything else.
    local ports
    local insecure_ports
    local portlist
    for (( i=1; i<=$num_instances; i++ )); do
        ports[$i]=`expr 8080 + $i`
        insecure_ports[$i]=`expr 9080 + $i`
    done

    portlist=$(IFS=, ; echo "${ports[*]}")

    #To preserve whitespace in echo commands...
    IFS='%'

    #buckets-api instances
    local buckets_api_xml_in=$SVC_ROOT/smf/manifests/buckets-api.xml.in
    for (( i=1; i<=$num_instances; i++ )); do
        local buckets_api_instance="buckets-api-${ports[i]}"
        local buckets_api_xml_out=$SVC_ROOT/smf/manifests/buckets-api-${ports[i]}.xml
        sed -e "s#@@BUCKETS_API_PORT@@#${ports[i]}#g" \
            -e "s#@@BUCKETS_API_INSECURE_PORT@@#${insecure_ports[i]}#g" \
            -e "s#@@BUCKETS_API_INSTANCE_NAME@@#$buckets_api_instance#g" \
            $buckets_api_xml_in  > $buckets_api_xml_out || \
            fatal "could not process $buckets_api_xml_in to $buckets_api_xml_out"

        svccfg import $buckets_api_xml_out || \
            fatal "unable to import $buckets_api_instance: $buckets_api_xml_out"
        svcadm enable "$buckets_api_instance" || \
            fatal "unable to start $buckets_api_instance"
        sleep 1
    done

    unset IFS

    # Now update our registration to publish the ports as SRV records
    RTPL="$SVC_ROOT/sapi_manifests/registrar/template"
    sed -e "s/@@PORTS@@/${portlist}/g" ${RTPL}.in > ${RTPL}

    # Wait until config-agent updates registrar's config before restarting
    # registrar.
    svcadm disable -st config-agent
    svcadm enable -st config-agent
    svcadm restart registrar

    local crontab=/tmp/.manta_webapi_cron
    crontab -l > $crontab

    echo "30 * * * * /opt/smartdc/buckets-api/bin/backup_pg_dumps.sh >> /var/log/backup_pg_dump.log 2>&1" >> $crontab
    [[ $? -eq 0 ]] || fatal "Unable to write to $crontab"
    crontab $crontab
    [[ $? -eq 0 ]] || fatal "Unable import crons"

    #.bashrc
    echo 'function req() { grep "$@" /var/log/buckets-api.log | bunyan ;}' \
        >>/root/.bashrc
}

# Mainline

echo "Running common setup scripts"
manta_common_presetup

echo "Adding local manifest directories"
manta_add_manifest_dir "/opt/smartdc/buckets-api"

manta_common2_setup "buckets-api"

manta_ensure_zk

echo "Setting up buckets-api"

# MANTA-1827
# Sometimes buckets-api instances come up before DNS resolvers are in /etc/resolv.conf
wait_for_resolv_conf
manta_setup_buckets_api

manta_common2_setup_log_rotation "buckets-api"

manta_common2_setup_end

exit 0
