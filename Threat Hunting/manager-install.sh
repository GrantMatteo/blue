#!/bin/bash

curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh && bash ./wazuh-install.sh -a -i
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh  -u admin -p 'NotTheRealPassword123?'

echo "
<agent_config>

    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>Microsoft-Windows-Windows Defender /Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>Security</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>System</location>
        <log_format>eventchannel</log_format>
    </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/auth.log</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/secure</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/apache2/access.log</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/httpd/access.log</location>
        </localfile>

        <localfile>
                <log_format>audit</log_format>
                <location>/var/log/audit/audit.log</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/remote/rsyslog.log</location>
        </localfile>
        <syscheck>
                <directories check_all="yes" whodata="yes">/etc</directories> 
                <directories check_all="yes" whodata="yes">/var/www</directories>
                <directories check_all="yes" whodata="yes">/root</directories>
                <directories check_all="yes" whodata="yes">/tmp</directories>
                <directories check_all="yes" whodata="yes">C:/Windows/Tasks</directories>
                <directories check_all="yes" whodata="yes">C:/Users/*/Appdata</directories>
                <directories check_all="yes" whodata="yes">C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine</directories> 
                <windows_registry arch="both" check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule</windows_registry>
                <windows_registry arch="both" check_all"yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree</windows_registry>
                <windows_registry arch="both" check_all="yes">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC</windows_registry>
                <windows_registry arch="both" check_all"yes">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS</windows_registry>
               
        </syscheck>
</agent_config>
" > /var/ossec/etc/shared/default/agent.conf


curl -so ~/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh

wget https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.10-1.msi -O /root/wazuh-agent.msi
curl -so /tmp/wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb
curl -so /tmp/wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.3.10-1.x86_64.rpm

systemctl restart wazuh-manager