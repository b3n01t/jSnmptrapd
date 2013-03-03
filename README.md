sample traps commands

sudo snmptrap -v 2c -c public localhost:1621 "" NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification netSnmpExampleHeartbeatRate i 123456

sudo snmptrap -m ALL -v 2c -c public localhost:1621 "" UCD-DEMO-MIB::ucdDemoPublic SNMPv2-MIB::sysLocation.0 s "Just here"