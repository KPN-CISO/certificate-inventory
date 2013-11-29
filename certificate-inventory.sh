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
OUTPUT_FILE="$(basename $0).$(date +%Y-%m-%d_%H:%M_%S).csv"
TMP_FILE="/tmp/$(basename $0).$$.tmp"
TIMEOUT=6
PARA=1000

DOWNLOADER="./download_certificate.sh"

################# Functions ##################
tool_check() {
    TOOL=$1

    which $TOOL >/dev/null 2>&1
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "Error: could not find $TOOL in the PATH. Please fix this or install $TOOL."
        exit 1
    fi
    return 0
}

usage() {
    echo "`basename $0` { [-o | --output ] <output file> } {-type [http|smtp|pop3|imap|ftp] } {--skip-tool-check} targethost:portnum {targethost:portnum {targethost:portnum {targethost:portnum ... } } }"
    echo "        --output <output file>          |   Output CSV file"
    echo "        -type http                      |   HTTPS testing on this port"
    echo "        -type smtp                      |   SMTP with StartTLS testing on this port"
    echo "        -type pop3                      |   POP3 with StartTLS testing on this port"
    echo "        -type imap                      |   IMAP with StartTLS testing on this port"
    echo "        -type ftp-ssl                   |   FTP with StartTLS testing on this port"
    echo "        --skip-tool-check               |   Skips the check for depending tools like sipcalc"
    echo "        targethost:portnum              |   Target host or netblock (hostname, IP or IP-block like 10.0.0.0/24) with a portnumber"
    echo ""
    exit 1
}

numberisoctet() {
    OCTET=$1

    expr $OCTET + 1 1>/dev/null 2>&1
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "Error: Input as an octet is not a number: $OCTET"
        return 1
    fi
    if [ $OCTET -ge 0 ] && [ $OCTET -lt 256 ]; then
        return 0
    fi
    echo "Error: Input is not an octet for an IP address: $OCTET"
    return 1
}

downloadcertificate() {
    HOST=$1
    PORT=$2

    echo "$HOST:$PORT"

    # Download the certificate, optionally with a specific StartTLS type
    if [ -n "$TYPE" ]; then
        echo | timeout 5 openssl s_client -connect ${HOST}:${PORT} -starttls $TYPE 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${TMP_FILE}"
    else
        echo | timeout 5 openssl s_client -connect ${HOST}:${PORT} 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${TMP_FILE}"
    fi

    if [ ! -s "${TMP_FILE}" ]; then
        rm "${TMP_FILE}"
        return 1
    fi

    KEYSIZE=$(openssl x509 -text -noout -in "${TMP_FILE}" 2>&1 | sed -e 's/^[[:blank:]]*//' | grep "RSA Public Key:" | cut -d')' -f 1 | cut -d'(' -f 2 | cut -d" " -f 1)
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


    rm "${TMP_FILE}"
    return 0
}

print_format_error_ip_block() {
    echo "The subnet $SUBNET needs to be written with 4 octets and a mask, example: 1.2.3.4/24" >&2
}

valid_ip() {
    IP=$1
    # Check if the numbers are IP addresses or too high/low
    OCTET_1=$(echo $IP | cut -d'.' -f 1)
    OCTET_2=$(echo $IP | cut -d'.' -f 2)
    OCTET_3=$(echo $IP | cut -d'.' -f 3)
    OCTET_4=$(echo $IP | cut -d'.' -f 4)

    numberisoctet $OCTET_1 || return 1
    numberisoctet $OCTET_2 || return 1
    numberisoctet $OCTET_3 || return 1
    numberisoctet $OCTET_4 || return 1

    return 0
}

valid_ip_block() {
    BLOCK=$1

    #Check if 4 octets are provided
    SUBNET=$(echo $BLOCK | cut -d'/' -f 1)
    TST=$(echo $SUBNET | cut -d'.' -f 4)
    if [ -z "$TST" ] || [ "$SUBNET" = "$TST" ]; then
        echo "The subnet $SUBNET needs to be written with 4 octets and a mask, example: 1.2.3.4/24" >&2
        return 1
    fi

    # Check mask
    MASK=$(echo $BLOCK | cut -d'/' -f 2)
    if [ -z $MASK ] || [ $MASK = $BLOCK ]; then
        print_format_error_ip_block
        return 1
    fi

    # Check mask value
    OCT_CNT=$(($MASK/8))
    if [ $OCT_CNT -ge 4 ]; then
        echo "The subnet mask is too big, example: 1.2.3.4/24" >&2
        exit 1
    fi

    # Check if the numbers are IP addresses or too high/low
    valid_ip $SUBNET
    RC=$?
    if [ $RC -ne 0 ]; then
        echo "The block IP is not OK, use 1.2.3.4, below 255." >&2
        exit 1
    fi

    echo "Valid block: ${SUBNET}/${MASK}" >&2
    return 0
}

calc_begin_ip() {
    BLOCK=$1
    if [ -z $BLOCK ]; then
        return 1
    fi

    USABLE_RANGE_RAW=$(sipcalc $BLOCK | grep "Usable range" | cut -d'-' -f 2 | sed -e 's/[[[:blank:]]//g')
    echo $USABLE_RANGE_RAW

    return 0
}

calc_end_ip() {
    BLOCK=$1
    if [ -z $BLOCK ]; then
        return 1
    fi

    USABLE_RANGE_RAW=$(sipcalc $BLOCK | grep "Usable range" | cut -d'-' -f 3 | sed -e 's/[[[:blank:]]//g')
    echo $USABLE_RANGE_RAW

    return 0
}


################## MAIN ###################

DO_TOOL_CHECK="yes"

while [ 1 ]; do
    if [ -z "$1" ]; then
        usage
    elif [ "$1" = "-type" ]; then
        shift
        if [ -z "$1" ]; then
            usage
        elif [ "$1" = "smtp" ]; then
            TYPE="smtp"
            shift
        elif [ "$1" = "pop3" ]; then
            TYPE="pop3"
            shift
        elif [ "$1" = "imap" ]; then
            TYPE="imap"
            shift
        elif [ "$1" = "ftp" ]; then
            TYPE="ftp"
            shift
        elif [ "$1" = "http" ]; then
            shift
            #HTTPS and non-starttls SSL/TLS
            TYPE=""
        else
            usage
        fi
    elif [ "$1" = "-o" ] || [ "$1" = "--output" ]; then
        shift
        OUTPUT_FILE=$1
        shift
    elif [ "$1" = "--skip-tool-check" ]; then
        shift
        DO_TOOL_CHECK="no"
    else
        break
    fi
done

# Add csv column title
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "\"Host\",\"Port\",\"Certificate Subject\",\"Issuer\",\"Keysize\",\"Serial\",\"Valid from date\",\"Valid until date\",\"self-signed\",\"Subject Alternative Names (DNS)\"" > "$OUTPUT_FILE"
fi

# Run over all of endpoints
while [ 1 ]; do
    OBJ=$1
    if [ -z "$OBJ" ]; then
        break
    fi

    #echo "OBJ: $OBJ"
    MASK=$(echo $OBJ | cut -d'/' -f 2)
    #echo "MASK: $MASK"

    if [ -z "$MASK" ] || [ "$MASK" = "$OBJ" ]; then
        HOST=$(echo $OBJ | cut -d':' -f 1)
        PORT=$(echo $OBJ | cut -d':' -f 2)
        if [ -z $HOST ]; then
            echo "No Host provided"
            usage
            exit 1
        fi
        if [ -z $PORT ] || [ "$PORT" = "$OBJ" ]; then
            echo "No Port provided with the Host"
            usage
            exit 1
        fi

        # Check mandatory depending tools
        if [ "$DO_TOOL_CHECK" = "yes" ]; then
            tool_check openssl
        fi
        # The downloader
        "${DOWNLOADER}" "$HOST" "$PORT" "$OUTPUT_FILE" "$TIMEOUT" "$TYPE"
    else
        BLOCK=$(echo $OBJ | cut -d':' -f 1)
        PORT=$(echo $OBJ | cut -d':' -f 2)
        if [ -z $BLOCK ]; then
            echo "No IP Block provided"
            usage
            exit 1
        fi
        if [ -z $PORT ] || [ "$PORT" = "$OBJ" ]; then
            echo "No Port provided with the block"
            usage
            exit 1
        fi

        valid_ip_block $BLOCK
        RC=$?
        if [ $RC -ne 0 ]; then
            exit 1
        fi

        # Check mandatory depending tools
        if [ "$DO_TOOL_CHECK" = "yes" ]; then
            tool_check sipcalc
        fi

        BEGIN_IP=$(calc_begin_ip $BLOCK)
        END_IP=$(calc_end_ip $BLOCK)

        # Check begin
        valid_ip $BEGIN_IP
        RC=$?
        if [ $RC -ne 0 ]; then
            echo "The begin IP is not OK, use 1.2.3.4, below 255." >&2
            exit 1
        fi

        # Check end
        valid_ip $END_IP
        RC=$?
        if [ $RC -ne 0 ]; then
            echo "The end IP is not OK, use 1.2.3.4, below 255." >&2
            exit 1
        fi


        echo "IP from: \"$BEGIN_IP to: $END_IP\" on port $PORT"

        OCTET_BEG_1=$(echo $BEGIN_IP | cut -d'.' -f 1)
        OCTET_BEG_2=$(echo $BEGIN_IP | cut -d'.' -f 2)
        OCTET_BEG_3=$(echo $BEGIN_IP | cut -d'.' -f 3)
        OCTET_BEG_4=$(echo $BEGIN_IP | cut -d'.' -f 4)

        OCTET_END_1=$(echo $END_IP | cut -d'.' -f 1)
        OCTET_END_2=$(echo $END_IP | cut -d'.' -f 2)
        OCTET_END_3=$(echo $END_IP | cut -d'.' -f 3)
        OCTET_END_4=$(echo $END_IP | cut -d'.' -f 4)

        for i in $(seq $OCTET_BEG_1 $OCTET_END_1); do
            for j in $(seq $OCTET_BEG_2 $OCTET_END_2); do
                for k in $(seq $OCTET_BEG_3  $OCTET_END_3); do
                    echo "Starting: $i.$j.$k.${OCTET_BEG_4}-${OCTET_END_4}"
                    echo
                    for l in $(seq $OCTET_BEG_4 $OCTET_END_4); do
                        echo -n "."

                        HOST="$i.$j.$k.$l"
                        CUR_PAR=$(ps | grep "${DOWNLOADER}" | wc -l | sed -e 's/[[:blank:]]//g')
                        while [ $CUR_PAR -ge $PARA ]; do
                            sleep 1
                            CUR_PAR=$(ps | grep "${DOWNLOADER}" | wc -l | sed -e 's/[[:blank:]]//g')
                        done

                        # Check mandatory depending tools
                        if [ "$DO_TOOL_CHECK" = "yes" ]; then
                            tool_check openssl
                        fi

                        # actual download
                        "${DOWNLOADER}" "$HOST" "$PORT" "$OUTPUT_FILE" "$TIMEOUT" "$TYPE" &
                    done
                    echo
                done
            done
        done
    fi

    shift
done


