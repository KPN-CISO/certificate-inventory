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
# Office: KPN CISO / Red Team - Ethical Hacker
# Project: Certs-on-Fire
# Date: September 14, 2013
# Version: 0.5
# License: GPLv3
##############################################

./certificate-inventory.sh --output output.csv 192.168.1.0/24:443 192.168.1.0/28:5001

