# cloudgate
connect with cloud, and do update if needed

usage:
    ./cloudgate cloudgate.ini

cloudgate.ini example:

<p><code>
[CLOUD]
#comment
#cloud api domain
base_domain=changes.kisslink.com.cn
#http timeout of connection between cloud & ap
request_timeout_seconds=30
connection_timeout_seconds=3

[LOCAL]
#how offen connect to cloud
check_time_interval=3
#ap version number
ap_version=1210
#aeskey to encrypt post data
aeskey=kisslinkkisslink

[CONFIG]
#list all files need to be watch
filename=/etc/router.conf
#set begin & end to extract specific section
begin_string="no vendor"
end_string="quit"
#when ap local file /etc/router.conf updated, trigger to run a system shell
trigger_command="service xxx restart"

filename=/etc/hosts
filename=/data/myservice.conf
</code></p>
