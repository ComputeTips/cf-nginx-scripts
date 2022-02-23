#!/bin/bash
#/etc/nginx/scripts/provision-nginx.sh
#v0.1
#This script provisions and secures a new NGINX web server installation.

readonly SCRIPT_VERSION="0.1"
readonly NGINX_LOCATION="/etc/nginx"
readonly NGINX_SCRIPTS_URL="https://github.com/ComputeTips/cf-nginx-scripts/archive/refs/tags/v$SCRIPT_VERSION.tar.gz"
readonly NGINX_SCRIPTS_LOCATION="$NGINX_LOCATION/scripts"
readonly NGINX_SCRIPTS_FILENAME="v$SCRIPT_VERSION.tar.gz"
readonly NGINX_SCROPTS_FOLDER_NAME="cf-nginx-scripts-$SCRIPT_VERSION"
readonly basic_settings="0-basic_settings.conf"
readonly cloudflare="1-cloudflare.conf"
readonly logging_format="2-logging_format.conf"
readonly logging_settings="3-logging_settings.conf"
readonly prevent_abuse="4-prevent_abuse.conf"
readonly gzip_settings="5-gzip_settings.conf"
readonly fastcgi_settings="6-fastcgi_settings.conf"
readonly default_server="7-default_server.conf"

readonly allow_only_admins_by_ip="allow_only_admins_by_ip.conf"
readonly listen_http_default_server="listen_http_default_server.conf"
readonly listen_http_global="listen_http_global.conf"
readonly listen_https_default_server="listen_https_default_server.conf"
readonly listen_https_global="listen_https_global.conf"
readonly ssl_settings="ssl_settings.conf"

readonly fastcgi_params="fastcgi_params"
readonly scgi_params="scgi_params"
readonly uwsgi_params="uwsgi_params"

readonly optional_fastcgi_params="fastcgi_params"

readonly mime_type="mime.types"

NGINX_CONF_FILE="user nginx nginx;\n"
NGINX_CONF_FILE+="worker_processes auto;\n"
NGINX_CONF_FILE+="worker_priority -10;\n"
NGINX_CONF_FILE+="\n"
NGINX_CONF_FILE+="events {\n"
NGINX_CONF_FILE+=" worker_connections 1024;\n"
NGINX_CONF_FILE+="}\n"
NGINX_CONF_FILE+="\n"
NGINX_CONF_FILE+="error_log /var/log/nginx/error.log notice;\n"
NGINX_CONF_FILE+="pid /var/run/nginx.pid;\n"
NGINX_CONF_FILE+="\n"
NGINX_CONF_FILE+="http {\n"
NGINX_CONF_FILE+=" include /etc/nginx/conf-enabled/*.conf;\n"
NGINX_CONF_FILE+=" include /etc/nginx/sites-enabled/*.conf;\n"
NGINX_CONF_FILE+="}\n"

NGX_BASIC_SETTINGS_FILE="default_type application/octet-stream;\n"
NGX_BASIC_SETTINGS_FILE+="keepalive_timeout 5;\n"
NGX_BASIC_SETTINGS_FILE+="\n"
NGX_BASIC_SETTINGS_FILE+="sendfile on;\n"
NGX_BASIC_SETTINGS_FILE+="tcp_nodelay on;\n"
NGX_BASIC_SETTINGS_FILE+="tcp_nopush on;\n"
NGX_BASIC_SETTINGS_FILE+="server_tokens off;\n"
NGX_BASIC_SETTINGS_FILE+="index index.php index.html index.htm;\n"
NGX_BASIC_SETTINGS_FILE+="include /etc/nginx/types-default/mime.types;\n"
NGX_BASIC_SETTINGS_FILE+="\n"
NGX_BASIC_SETTINGS_FILE+="client_body_buffer_size 16K;\n"
NGX_BASIC_SETTINGS_FILE+="client_header_buffer_size 1k;\n"
NGX_BASIC_SETTINGS_FILE+="large_client_header_buffers 4 8k;\n"
NGX_BASIC_SETTINGS_FILE+="client_max_body_size 256k;\n"
NGX_BASIC_SETTINGS_FILE+="\n"
NGX_BASIC_SETTINGS_FILE+="client_body_timeout 10;\n"
NGX_BASIC_SETTINGS_FILE+="client_header_timeout 10;\n"
NGX_BASIC_SETTINGS_FILE+="send_timeout 10;\n"
NGX_BASIC_SETTINGS_FILE+="\n"
NGX_BASIC_SETTINGS_FILE+="open_file_cache max=4096 inactive=30s;\n"
NGX_BASIC_SETTINGS_FILE+="open_file_cache_valid 30s;\n"
NGX_BASIC_SETTINGS_FILE+="open_file_cache_min_uses 2;\n"

NGX_LOGGING_FORMAT_FILE='log_format main '\''$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"'\'';\n';

NGX_LOGGING_SETTINGS_FILE="#access_log /var/log/nginx/access.log main;\n"
NGX_LOGGING_SETTINGS_FILE+="access_log off;\n"
NGX_LOGGING_SETTINGS_FILE+="error_log /var/log/nginx/error.log error;\n"

NGX_PREVENT_ABUSE_FILE='limit_req_zone $binary_remote_addr zone=wpsearch:1m rate=1r/s;\n';
NGX_PREVENT_ABUSE_FILE+='limit_conn_zone $binary_remote_addr zone=phplimit:1m;\n';
NGX_PREVENT_ABUSE_FILE+="\n"
NGX_PREVENT_ABUSE_FILE+="limit_conn_log_level info;\n"
NGX_PREVENT_ABUSE_FILE+="limit_req_log_level info;\n"

NGX_GZIP_SETTINGS_FILE="gzip on;\n"
NGX_GZIP_SETTINGS_FILE+='gzip_disable "MSIE [1-6]\.(?!.*SV1)";\n';
NGX_GZIP_SETTINGS_FILE+="\n"
NGX_GZIP_SETTINGS_FILE+="gzip_vary on;\n"
NGX_GZIP_SETTINGS_FILE+="gzip_proxied any;\n"
NGX_GZIP_SETTINGS_FILE+="gzip_comp_level 6;\n"
NGX_GZIP_SETTINGS_FILE+="gzip_buffers 64 8k;\n"
NGX_GZIP_SETTINGS_FILE+="gzip_http_version 1.1;\n"
NGX_GZIP_SETTINGS_FILE+="gzip_min_length 1024;\n"
NGX_GZIP_SETTINGS_FILE+="gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;\n"

NGX_FCGI_SETTINGS_FILE="fastcgi_intercept_errors on;\n"
NGX_FCGI_SETTINGS_FILE+="fastcgi_ignore_client_abort on;\n"
NGX_FCGI_SETTINGS_FILE+="fastcgi_max_temp_file_size 0;\n"
NGX_FCGI_SETTINGS_FILE+="fastcgi_buffers 256 8k;\n"
NGX_FCGI_SETTINGS_FILE+="fastcgi_read_timeout 60;\n"
NGX_FCGI_SETTINGS_FILE+="fastcgi_index index.php;\n"

NGX_DEFAULT_SERVER_FILE="server {\n"
NGX_DEFAULT_SERVER_FILE+=" include /etc/nginx/conf-optional/listen_http_default_server.conf;\n"
NGX_DEFAULT_SERVER_FILE+=" server_name _;\n"
NGX_DEFAULT_SERVER_FILE+=" return 403;\n"
NGX_DEFAULT_SERVER_FILE+="}\n"
NGX_DEFAULT_SERVER_FILE+="\n"
NGX_DEFAULT_SERVER_FILE+="server {\n"
NGX_DEFAULT_SERVER_FILE+=" include /etc/nginx/conf-optional/listen_https_default_server.conf;\n"
NGX_DEFAULT_SERVER_FILE+=" server_name _;\n"
NGX_DEFAULT_SERVER_FILE+=" ssl_certificate /etc/nginx/ssl/blank_server.crt;\n"
NGX_DEFAULT_SERVER_FILE+=" ssl_certificate_key /etc/nginx/ssl/blank_server.key;\n"
NGX_DEFAULT_SERVER_FILE+=" ssl_dhparam /etc/nginx/ssl/ssl_dhparams.pem;\n"
NGX_DEFAULT_SERVER_FILE+=" include /etc/nginx/conf-optional/ssl_settings.conf;\n"
NGX_DEFAULT_SERVER_FILE+=" return 403;\n"
NGX_DEFAULT_SERVER_FILE+="}\n"

NGX_ALLOW_ONLY_ADMINS_FILE="deny all;\n"

NGX_LISTEN_HTTP_DEFAULT_SERVER_FILE="listen 80 default_server;\n"
NGX_LISTEN_HTTP_DEFAULT_SERVER_FILE+="listen [::]:80 default_server;\n"

NGX_LISTEN_HTTP_GLOBAL_FILE="listen 80;\n"
NGX_LISTEN_HTTP_GLOBAL_FILE+="listen [::]:80;\n"

NGX_LISTEN_HTTPS_DEFUALT_SERVER_FILE="listen 443 ssl http2 default_server;\n"
NGX_LISTEN_HTTPS_DEFUALT_SERVER_FILE+="listen [::]:443 ssl http2 default_server;\n"

NGX_LISTEN_HTTPS_GLOBAL_FILE="listen 144.202.17.221:443 ssl http2;\n"
NGX_LISTEN_HTTPS_GLOBAL_FILE+="listen [2001:19f0:5401:236e:1:5ee:bad:c0de]:443 ssl http2;\n"

NGX_SSL_SETTINGS_FILE="ssl_session_cache shared:le_nginx_SSL:10m;\n"
NGX_SSL_SETTINGS_FILE+="ssl_session_timeout 1440m;\n"
NGX_SSL_SETTINGS_FILE+="ssl_session_tickets off;\n"
NGX_SSL_SETTINGS_FILE+="\n"
NGX_SSL_SETTINGS_FILE+="ssl_protocols TLSv1.2 TLSv1.3;\n"
NGX_SSL_SETTINGS_FILE+="ssl_prefer_server_ciphers off;\n"
NGX_SSL_SETTINGS_FILE+="\n"
NGX_SSL_SETTINGS_FILE+='ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";\n';

NGX_FCGI_PARAMS_FILE='fastcgi_param  QUERY_STRING       $query_string;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  REQUEST_METHOD     $request_method;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  CONTENT_TYPE       $content_type;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  CONTENT_LENGTH     $content_length;\n';
NGX_FCGI_PARAMS_FILE+="\n"
NGX_FCGI_PARAMS_FILE+='fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  REQUEST_URI        $request_uri;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  DOCUMENT_URI       $document_uri;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  DOCUMENT_ROOT      $document_root;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_PROTOCOL    $server_protocol;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  REQUEST_SCHEME     $scheme;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  HTTPS              $https if_not_empty;\n';
NGX_FCGI_PARAMS_FILE+="\n"
NGX_FCGI_PARAMS_FILE+="fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;\n"
NGX_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;\n';
NGX_FCGI_PARAMS_FILE+="\n"
NGX_FCGI_PARAMS_FILE+='fastcgi_param  REMOTE_ADDR        $remote_addr;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  REMOTE_PORT        $remote_port;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_ADDR        $server_addr;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_PORT        $server_port;\n';
NGX_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_NAME        $server_name;\n';
NGX_FCGI_PARAMS_FILE+="\n"
NGX_FCGI_PARAMS_FILE+="fastcgi_param  REDIRECT_STATUS    200;\n"

NGX_SCGI_PARAMS_FILE='scgi_param  REQUEST_METHOD     $request_method;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  REQUEST_URI        $request_uri;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  QUERY_STRING       $query_string;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  CONTENT_TYPE       $content_type;\n';
NGX_SCGI_PARAMS_FILE+="\n"
NGX_SCGI_PARAMS_FILE+='scgi_param  DOCUMENT_URI       $document_uri;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  DOCUMENT_ROOT      $document_root;\n';
NGX_SCGI_PARAMS_FILE+="scgi_param  SCGI               1;\n"
NGX_SCGI_PARAMS_FILE+='scgi_param  SERVER_PROTOCOL    $server_protocol;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  REQUEST_SCHEME     $scheme;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  HTTPS              $https if_not_empty;\n';
NGX_SCGI_PARAMS_FILE+="\n"
NGX_SCGI_PARAMS_FILE+='scgi_param  REMOTE_ADDR        $remote_addr;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  REMOTE_PORT        $remote_port;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  SERVER_PORT        $server_port;\n';
NGX_SCGI_PARAMS_FILE+='scgi_param  SERVER_NAME        $server_name;\n';

NGX_UWSGI_PARAMS_FILE='uwsgi_param  QUERY_STRING       $query_string;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  REQUEST_METHOD     $request_method;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  CONTENT_TYPE       $content_type;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  CONTENT_LENGTH     $content_length;\n';
NGX_UWSGI_PARAMS_FILE+="\n"
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  REQUEST_URI        $request_uri;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  PATH_INFO          $document_uri;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  DOCUMENT_ROOT      $document_root;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  SERVER_PROTOCOL    $server_protocol;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  REQUEST_SCHEME     $scheme;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  HTTPS              $https if_not_empty;\n';
NGX_UWSGI_PARAMS_FILE+="\n"
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  REMOTE_ADDR        $remote_addr;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  REMOTE_PORT        $remote_port;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  SERVER_PORT        $server_port;\n';
NGX_UWSGI_PARAMS_FILE+='uwsgi_param  SERVER_NAME        $server_name;\n';

NGX_OPT_FCGI_PARAMS_FILE='fastcgi_param  QUERY_STRING       $query_string;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  REQUEST_METHOD     $request_method;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  CONTENT_TYPE       $content_type;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  CONTENT_LENGTH     $content_length;\n';
NGX_OPT_FCGI_PARAMS_FILE+="\n"
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  REQUEST_URI        $request_uri;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  DOCUMENT_URI       $document_uri;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  DOCUMENT_ROOT      $document_root;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_PROTOCOL    $server_protocol;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  HTTPS              $https if_not_empty;\n';
NGX_OPT_FCGI_PARAMS_FILE+="\n"
NGX_OPT_FCGI_PARAMS_FILE+="fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;\n"
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;\n';
NGX_OPT_FCGI_PARAMS_FILE+="\n"
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  REMOTE_ADDR        $remote_addr;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  REMOTE_PORT        $remote_port;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_ADDR        $server_addr;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_PORT        $server_port;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SERVER_NAME        $server_name;\n';
NGX_OPT_FCGI_PARAMS_FILE+='fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;\n';
NGX_OPT_FCGI_PARAMS_FILE+="\n"
NGX_OPT_FCGI_PARAMS_FILE+="fastcgi_param  REDIRECT_STATUS    200;\n"

NGX_MIME_TYPES_FILE="types {\n"
NGX_MIME_TYPES_FILE+="    text/html                                        html htm shtml;\n"
NGX_MIME_TYPES_FILE+="    text/css                                         css;\n"
NGX_MIME_TYPES_FILE+="    text/xml                                         xml;\n"
NGX_MIME_TYPES_FILE+="    image/gif                                        gif;\n"
NGX_MIME_TYPES_FILE+="    image/jpeg                                       jpeg jpg;\n"
NGX_MIME_TYPES_FILE+="    application/javascript                           js;\n"
NGX_MIME_TYPES_FILE+="    application/atom+xml                             atom;\n"
NGX_MIME_TYPES_FILE+="    application/rss+xml                              rss;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    text/mathml                                      mml;\n"
NGX_MIME_TYPES_FILE+="    text/plain                                       txt;\n"
NGX_MIME_TYPES_FILE+="    text/vnd.sun.j2me.app-descriptor                 jad;\n"
NGX_MIME_TYPES_FILE+="    text/vnd.wap.wml                                 wml;\n"
NGX_MIME_TYPES_FILE+="    text/x-component                                 htc;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    image/png                                        png;\n"
NGX_MIME_TYPES_FILE+="    image/svg+xml                                    svg svgz;\n"
NGX_MIME_TYPES_FILE+="    image/tiff                                       tif tiff;\n"
NGX_MIME_TYPES_FILE+="    image/vnd.wap.wbmp                               wbmp;\n"
NGX_MIME_TYPES_FILE+="    image/webp                                       webp;\n"
NGX_MIME_TYPES_FILE+="    image/x-icon                                     ico;\n"
NGX_MIME_TYPES_FILE+="    image/x-jng                                      jng;\n"
NGX_MIME_TYPES_FILE+="    image/x-ms-bmp                                   bmp;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    font/woff                                        woff;\n"
NGX_MIME_TYPES_FILE+="    font/woff2                                       woff2;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    application/java-archive                         jar war ear;\n"
NGX_MIME_TYPES_FILE+="    application/json                                 json;\n"
NGX_MIME_TYPES_FILE+="    application/mac-binhex40                         hqx;\n"
NGX_MIME_TYPES_FILE+="    application/msword                               doc;\n"
NGX_MIME_TYPES_FILE+="    application/pdf                                  pdf;\n"
NGX_MIME_TYPES_FILE+="    application/postscript                           ps eps ai;\n"
NGX_MIME_TYPES_FILE+="    application/rtf                                  rtf;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.apple.mpegurl                    m3u8;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.google-earth.kml+xml             kml;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.google-earth.kmz                 kmz;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.ms-excel                         xls;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.ms-fontobject                    eot;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.ms-powerpoint                    ppt;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.oasis.opendocument.graphics      odg;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.oasis.opendocument.presentation  odp;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.oasis.opendocument.spreadsheet   ods;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.oasis.opendocument.text          odt;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.openxmlformats-officedocument.presentationml.presentation\n"
NGX_MIME_TYPES_FILE+="                                                     pptx;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\n"
NGX_MIME_TYPES_FILE+="                                                     xlsx;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.openxmlformats-officedocument.wordprocessingml.document\n"
NGX_MIME_TYPES_FILE+="                                                     docx;\n"
NGX_MIME_TYPES_FILE+="    application/vnd.wap.wmlc                         wmlc;\n"
NGX_MIME_TYPES_FILE+="    application/x-7z-compressed                      7z;\n"
NGX_MIME_TYPES_FILE+="    application/x-cocoa                              cco;\n"
NGX_MIME_TYPES_FILE+="    application/x-java-archive-diff                  jardiff;\n"
NGX_MIME_TYPES_FILE+="    application/x-java-jnlp-file                     jnlp;\n"
NGX_MIME_TYPES_FILE+="    application/x-makeself                           run;\n"
NGX_MIME_TYPES_FILE+="    application/x-perl                               pl pm;\n"
NGX_MIME_TYPES_FILE+="    application/x-pilot                              prc pdb;\n"
NGX_MIME_TYPES_FILE+="    application/x-rar-compressed                     rar;\n"
NGX_MIME_TYPES_FILE+="    application/x-redhat-package-manager             rpm;\n"
NGX_MIME_TYPES_FILE+="    application/x-sea                                sea;\n"
NGX_MIME_TYPES_FILE+="    application/x-shockwave-flash                    swf;\n"
NGX_MIME_TYPES_FILE+="    application/x-stuffit                            sit;\n"
NGX_MIME_TYPES_FILE+="    application/x-tcl                                tcl tk;\n"
NGX_MIME_TYPES_FILE+="    application/x-x509-ca-cert                       der pem crt;\n"
NGX_MIME_TYPES_FILE+="    application/x-xpinstall                          xpi;\n"
NGX_MIME_TYPES_FILE+="    application/xhtml+xml                            xhtml;\n"
NGX_MIME_TYPES_FILE+="    application/xspf+xml                             xspf;\n"
NGX_MIME_TYPES_FILE+="    application/zip                                  zip;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    application/octet-stream                         bin exe dll;\n"
NGX_MIME_TYPES_FILE+="    application/octet-stream                         deb;\n"
NGX_MIME_TYPES_FILE+="    application/octet-stream                         dmg;\n"
NGX_MIME_TYPES_FILE+="    application/octet-stream                         iso img;\n"
NGX_MIME_TYPES_FILE+="    application/octet-stream                         msi msp msm;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    audio/midi                                       mid midi kar;\n"
NGX_MIME_TYPES_FILE+="    audio/mpeg                                       mp3;\n"
NGX_MIME_TYPES_FILE+="    audio/ogg                                        ogg;\n"
NGX_MIME_TYPES_FILE+="    audio/x-m4a                                      m4a;\n"
NGX_MIME_TYPES_FILE+="    audio/x-realaudio                                ra;\n"
NGX_MIME_TYPES_FILE+="\n"
NGX_MIME_TYPES_FILE+="    video/3gpp                                       3gpp 3gp;\n"
NGX_MIME_TYPES_FILE+="    video/mp2t                                       ts;\n"
NGX_MIME_TYPES_FILE+="    video/mp4                                        mp4;\n"
NGX_MIME_TYPES_FILE+="    video/mpeg                                       mpeg mpg;\n"
NGX_MIME_TYPES_FILE+="    video/quicktime                                  mov;\n"
NGX_MIME_TYPES_FILE+="    video/webm                                       webm;\n"
NGX_MIME_TYPES_FILE+="    video/x-flv                                      flv;\n"
NGX_MIME_TYPES_FILE+="    video/x-m4v                                      m4v;\n"
NGX_MIME_TYPES_FILE+="    video/x-mng                                      mng;\n"
NGX_MIME_TYPES_FILE+="    video/x-ms-asf                                   asx asf;\n"
NGX_MIME_TYPES_FILE+="    video/x-ms-wmv                                   wmv;\n"
NGX_MIME_TYPES_FILE+="    video/x-msvideo                                  avi;\n"
NGX_MIME_TYPES_FILE+="}\n"

if [ -d "$NGINX_LOCATION" ]
then
        echo "It looks like $NGINX_LOCATION already exists. If you choose to continue, it will be renamed to $NGINX_LOCATION.bak."
        read -p "Do you wish to continue [y|N]" -n 1 -r
        echo -e "\n"
        if [[ ! $REPLY =~ ^[Yy]$ ]]
        then
            exit 1
        fi
        if [ -d $NGINX_LOCATION.bak ]
        then
            echo "It looks like $NGINX_LOCATION.bak already exists. Cannot continue, exiting."
            exit 1
        fi
        mv $NGINX_LOCATION $NGINX_LOCATION.bak
fi

echo "Provisioning NGINX..."
mkdir $NGINX_LOCATION
mkdir $NGINX_LOCATION/cloudflare
mkdir $NGINX_LOCATION/conf-available
mkdir $NGINX_LOCATION/conf-enabled
mkdir $NGINX_LOCATION/conf-optional
mkdir $NGINX_LOCATION/params-default
mkdir $NGINX_LOCATION/params-optional
mkdir $NGINX_SCRIPTS_LOCATION
mkdir $NGINX_LOCATION/sites-available
mkdir $NGINX_LOCATION/sites-enabled
mkdir $NGINX_LOCATION/ssl
mkdir $NGINX_LOCATION/types-default
mkdir $NGINX_LOCATION/types-optional
ln -s /../../usr/lib64/nginx/modules $NGINX_LOCATION/modules
touch $NGINX_LOCATION/nginx.conf
echo -e $NGINX_CONF_FILE >> $NGINX_LOCATION/nginx.conf
touch $NGINX_LOCATION/conf-available/$basic_settings
touch $NGINX_LOCATION/conf-available/$cloudflare
touch $NGINX_LOCATION/conf-available/$logging_format
touch $NGINX_LOCATION/conf-available/$logging_settings
touch $NGINX_LOCATION/conf-available/$prevent_abuse
touch $NGINX_LOCATION/conf-available/$gzip_settings
touch $NGINX_LOCATION/conf-available/$fastcgi_settings
touch $NGINX_LOCATION/conf-available/$default_server

echo -e $NGX_BASIC_SETTINGS_FILE >> $NGINX_LOCATION/conf-available/$basic_settings
echo -e $NGX_LOGGING_FORMAT_FILE >> $NGINX_LOCATION/conf-available/$logging_format
echo -e $NGX_LOGGING_SETTINGS_FILE >> $NGINX_LOCATION/conf-available/$logging_settings
echo -e $NGX_PREVENT_ABUSE_FILE >> $NGINX_LOCATION/conf-available/$prevent_abuse
echo -e $NGX_GZIP_SETTINGS_FILE >> $NGINX_LOCATION/conf-available/$gzip_settings
echo -e $NGX_FCGI_SETTINGS_FILE >> $NGINX_LOCATION/conf-available/$fastcgi_settings
echo -e $NGX_DEFAULT_SERVER_FILE >> $NGINX_LOCATION/conf-available/$default_server

touch $NGINX_LOCATION/conf-optional/$allow_only_admins_by_ip
touch $NGINX_LOCATION/conf-optional/$listen_http_default_server
touch $NGINX_LOCATION/conf-optional/$listen_http_global
touch $NGINX_LOCATION/conf-optional/$listen_https_default_server
touch $NGINX_LOCATION/conf-optional/$listen_https_global
touch $NGINX_LOCATION/conf-optional/$ssl_settings

echo -e $NGX_ALLOW_ONLY_ADMINS_FILE >> $NGINX_LOCATION/conf-optional/$allow_only_admins_by_ip
echo -e $NGX_LISTEN_HTTP_DEFAULT_SERVER_FILE >> $NGINX_LOCATION/conf-optional/$listen_http_default_server
echo -e $NGX_LISTEN_HTTP_GLOBAL_FILE >> $NGINX_LOCATION/conf-optional/$listen_http_global
echo -e $NGX_LISTEN_HTTPS_DEFUALT_SERVER_FILE >> $NGINX_LOCATION/conf-optional/$listen_https_default_server
echo -e $NGX_LISTEN_HTTPS_GLOBAL_FILE >> $NGINX_LOCATION/conf-optional/$listen_https_global
echo -e $NGX_SSL_SETTINGS_FILE >> $NGINX_LOCATION/conf-optional/$ssl_settings

touch $NGINX_LOCATION/params-default/$fastcgi_params
touch $NGINX_LOCATION/params-default/$scgi_params
touch $NGINX_LOCATION/params-default/$uwsgi_params

echo -e $NGX_FCGI_PARAMS_FILE >> $NGINX_LOCATION/params-default/$fastcgi_params
echo -e $NGX_SCGI_PARAMS_FILE >> $NGINX_LOCATION/params-default/$scgi_params
echo -e $NGX_UWSGI_PARAMS_FILE >> $NGINX_LOCATION/params-default/$uwsgi_params

touch $NGINX_LOCATION/params-optional/$optional_fastcgi_params
echo -e $NGX_OPT_FCGI_PARAMS_FILE >> $NGINX_LOCATION/params-optional/$optional_fastcgi_params

touch $NGINX_LOCATION/types-default/$mime_type
echo -e $NGX_MIME_TYPES_FILE >> $NGINX_LOCATION/types-default/$mime_type

ln -s $NGINX_LOCATION/conf-available/$basic_settings $NGINX_LOCATION/conf-enabled/$basic_settings
ln -s $NGINX_LOCATION/conf-available/$cloudflare $NGINX_LOCATION/conf-enabled/$cloudflare
ln -s $NGINX_LOCATION/conf-available/$logging_format $NGINX_LOCATION/conf-enabled/$logging_format
ln -s $NGINX_LOCATION/conf-available/$logging_settings $NGINX_LOCATION/conf-enabled/$logging_settings
ln -s $NGINX_LOCATION/conf-available/$prevent_abuse $NGINX_LOCATION/conf-enabled/$prevent_abuse
ln -s $NGINX_LOCATION/conf-available/$gzip_settings $NGINX_LOCATION/conf-enabled/$gzip_settings
ln -s $NGINX_LOCATION/conf-available/$fastcgi_settings $NGINX_LOCATION/conf-enabled/$fastcgi_settings
ln -s $NGINX_LOCATION/conf-available/$default_server $NGINX_LOCATION/conf-enabled/$default_server

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout $NGINX_LOCATION/ssl/blank_server.key -out $NGINX_LOCATION/ssl/blank_server.crt
openssl dhparam -out $NGINX_LOCATION/ssl/ssl_dhparams.pem 2048

chmod 0750 $NGINX_LOCATION
wget -O $NGINX_SCRIPTS_LOCATION/$NGINX_SCRIPTS_FILENAME $NGINX_SCRIPTS_URL
tar -xf $NGINX_SCRIPTS_LOCATION/$NGINX_SCRIPTS_FILENAME --directory $NGINX_SCRIPTS_LOCATION
rm -f $NGINX_SCRIPTS_LOCATION/$NGINX_SCRIPTS_FILENAME
mv $NGINX_SCRIPTS_LOCATION/$NGINX_SCROPTS_FOLDER_NAME/*.sh $NGINX_SCRIPTS_LOCATION
rm -fR $NGINX_SCRIPTS_LOCATION/$NGINX_SCROPTS_FOLDER_NAME
find "${NGINX_LOCATION}" -type d -exec chmod 0740 "{}" \;
find "${NGINX_LOCATION}" -type f -exec chmod 0640 "{}" \;
find "${NGINX_SCRIPTS_LOCATION}" -type f -exec chmod 0740 "{}" \;
chown -R root:nginx $NGINX_LOCATION

