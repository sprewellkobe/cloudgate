#cloudgate
connect with cloud and report md5 of local config files to the cloud

if cloud's version is newer than local, update local config files

otherwise, upload the newer local config files to cloud server

##how to use

usage:
    ./cloudgate cloudgate.ini

cloudgate.ini example:

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
    ap_version=NBOS-1.0.3.1507
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
    #when ap local file /etc/router.conf updated, trigger to send message "ok" to unix socket /tmp/sdd.sock
    trigger_unix_socket="/tmp/sdd.sock"

    filename=/etc/hosts
    filename=/data/myservice.conf

#how it works

    while(true)
         {
          if file_exists /tmp/cloudgate_reload_config
            {
             reload config
             rm /tmp/cloudgate_reload_config
             continue
            }
          if file_exists /tmp/ap_just_after_reset
            {
             if( curl cloud api to notify ap leave all groups == ok)
                unlink /tmp/ap_just_after_reset
             continue;
            }
          compare local_config with cloud_config
          if(local_config == cloud_config)
             continue
          if(cloud_config newer than local_config)
             local_config=cloud_config
          else
            {
             upload local_config to cloud
             cloud_config=local_config
            }
          sleep
         }
         
API: http://kisswiki.sinaapp.com/debug.kisslink.com接口

#how to reload config

touch /tmp/cloudgate_reload_config
