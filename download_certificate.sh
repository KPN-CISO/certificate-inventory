#!/bin/bash

##############################################
# This file is part of certificate-inventory.
#
# certificate-inventory is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# certificate-inventory is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# certificate-inventory. If not, see <http://www.gnu.org/licenses/>.
##############################################

##############################################
# Author: Oscar Koeroo <oscar.koeroo@kpn.com>
# Office: CISO / Red Team - Ethical Hacker
# Project: Certs-on-Fire
# Date: September 14, 2013
# Version: 0.5
# License: GPLv3
##############################################

################# Global vars #################
TYPE=""
TMP_FILE="/tmp/$(basename $0).$$.$(date +%s).tmp"

downloadcertificate() {
    HOST="$1"
    PORT="$2"
    OUTPUT_FILE="$3"
    TIMEOUT="$4"
    TYPE="$5"

    # Download the certificate, optionally with a specific StartTLS type
    if [ -n "$TYPE" ]; then
        echo | openssl s_client -connect ${HOST}:${PORT} -starttls $TYPE 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${TMP_FILE}" &
    else
        echo | openssl s_client -connect ${HOST}:${PORT} 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${TMP_FILE}" &
    fi
    PID=$!

    SECONDS=0
    while [ 1 ]; do
        kill -0 $PID >/dev/null 2>&1
        RC=$?

        if [ $RC -eq 0 ]; then
            sleep 1
            SECONDS=$((SECONDS+1))
        else
            break
        fi

        if [ $SECONDS -gt 4 ]; then
            kill -9 $PID >/dev/null 2>&1
            break;
        fi
    done

    if [ ! -s "${TMP_FILE}" ]; then
        return 1
    fi

    KEYSIZE=$(openssl x509 -text -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/^[[:blank:]]*//' | grep 'Public[ -]Key:' | cut -d')' -f 1 | cut -d'(' -f 2 | cut -d" " -f 1)
    SUBJECT=$(openssl x509 -subject -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/subject= //' -e 's/"/""/g')
    ISSUER=$(openssl x509 -issuer -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/issuer= //' -e 's/"/""/g')
    START_DT=$(openssl x509 -startdate -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/notBefore=//' -e 's/"/""/g')
    END_DT=$(openssl x509 -enddate -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/notAfter=//' -e 's/"/""/g')
    SERIAL=$(openssl x509 -serial -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/serial=//' -e 's/"/""/g')
    SANS=$(openssl x509 -text -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/^[[:blank:]]*//' | grep "DNS:")

    if [ "$ISSUER" = "$SUBJECT" ]; then
        SELF_SIGNED="yes"
    else
        SELF_SIGNED="no"
    fi

    echo "\"${HOST}\",\"${PORT}\",\"$SUBJECT\",\"$ISSUER\",\"$KEYSIZE\",\"$SERIAL\",\"$START_DT\",\"$END_DT\",\"$SELF_SIGNED\",\"$SANS\"" >> "$OUTPUT_FILE"
    return 0
}

if [ $# -lt 4 ]; then
    echo "Error: Expecting 4 or 5 arguments: 1. Host/IP 2. Port 3. output file, 4. Timeout in seconds 5. (optional) TLS type" >&2
    exit 1
fi

downloadcertificate "$1" "$2" "$3" "$4" "$5"
RC=$?
rm "${TMP_FILE}"
exit $RC
