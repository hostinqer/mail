# mail
Postfix/Dovecot
Настройка postfix + dovecot + mysql база + postfixadmin + roundcube + dkim на CentOS 8

Примечание устанавливаем php 7.4 чтобы было меньше проблем,а если php 8 , то нужно установить новые версии.

Для начала настраиваем зону, hostname = mail.domain.az и меняем ptr запись mail.domain.az , mx прописывем domain.az = mail.domain.az


Установка postfixadmin

Начнем с установки и настройки панели управления почтовым сервером postfix — postfixadmin.Без него начинать что-то делать неудобно, так как управлять пользователями, ящиками, алиасами будет нечем.

Подключаем репозиторий remi с дополнительными пакетами для php (нужен для php-imap), обновляем кэш.

# dnf install dnf-utils http://rpms.remirepo.net/enterprise/remi-release-8.rpm
# dnf makecache
# dnf module enable php:remi-7.2

# dnf install httpd php mariadb mariadb-server php-imap php-mysqlnd php-mbstring

systemctl enable --now httpd

# systemctl enable --now mariadb
# /usr/bin/mysql_secure_installation

# wget https://sourceforge.net/projects/postfixadmin/files/postfixadmin/postfixadmin-3.2/postfixadmin-3.2.4.tar.gz 
на моменнт установки можно утсановить новую версию

Распаковываем и копируем в директорию web сервера.

# tar xzvf postfixadmin-3.2.4.tar.gz
# mkdir /var/www/html/padmin
# cp -R /root/postfixadmin-3.2.4/* /var/www/html/padmin
# chown -R apache. /var/www/html/padmin

Создаем /var/www/html/padmin/config.local.php файл и вставляем туда 	

$CONF['configured'] = true;
$CONF['default_language'] = 'ru';
$CONF['database_type'] = 'mysqli';
$CONF['database_host'] = 'localhost';
$CONF['database_user'] = 'postfix';
$CONF['database_password'] = '123';
$CONF['database_name'] = 'postfix';
$CONF['admin_email'] = 'root@domain.az';
$CONF['encrypt'] = 'md5crypt';
$CONF['domain_path'] = 'YES';
$CONF['domain_in_mailbox'] = 'YES';
$CONF['transport_default'] = 'virtual';
$CONF['show_footer_text'] = 'YES';
$CONF['footer_text'] = 'Return to http://5.180.137.106/padmin/public/';
$CONF['footer_link'] = 'http://5.180.137.106/padmin/public/';
$CONF['default_aliases'] = array (
 'abuse' => 'root',
 'hostmaster' => 'root',
 'postmaster' => 'root',
 'webmaster' => 'root'
);


Для работы панели управления нужна директория templates_c с правами на запись для web сервера. Сделаем ее и дадим права.

# mkdir /var/www/html/padmin/templates_c
# chown -R apache. /var/www/html/padmin/templates_c

Идем по адресу http://ip/padmin/public/setup.php и начинаем установку postfixadmin. Первым делом идет проверка всех необходимых для установки и работы компонентов


В самом низу страницы будет интерфейс добавления администратора панели управления. Создаем его.
При первом добавлении учетной записи вы введете пароль для поля Setup password.
Вам будет выведен правильный хэш. Добавьте его в конфиг config.local.php.

$CONF['setup_password'] = '555e082774c7b3584af0a09e45657532:43ce9c34ca00f681a002c2ea40354d7f1d68768a';

После этого добавляйте учетную запись администратора панели еще раз, используя тот же самый пароль установки, хэш от которого вы добавили. Попробуйте залогиниться под этой учетной записью по адресу http://5.180.137.106/padmin/public/.

Теперь нам нужно добавить домен в панель управления. Идем в раздел Список доменов -> Новый домен и добавляем свой домен.
На этом установку и настройку postfixadmin завершаем. Интерфейс для управления почтовым сервером мы подготовили. Теперь можно заняться непосредственно настройкой postfix.

Установка Postfix
# dnf install postfix postfix-mysql

Приводим конфиг postfix /etc/postfix/main.cf к следующему виду.

soft_bounce = no
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix

myhostname = mail.domain.az
mydomain = domain.az
myorigin = $myhostname

inet_interfaces = all
inet_protocols = ipv4

mydestination = localhost.$mydomain, localhost
unknown_local_recipient_reject_code = 550
mynetworks = 127.0.0.0/8, 10.1.4.22/32

alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

smtpd_banner = $myhostname ESMTP $mail_name

debug_peer_level = 2
# Строки с PATH и ddd должны быть с отступом в виде табуляции от начала строки
debugger_command =
    PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
    ddd $daemon_directory/$process_name $process_id & sleep 5

sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix
setgid_group = postdrop
html_directory = no
manpage_directory = /usr/share/man
sample_directory = /usr/share/doc/postfix-2.10.1/samples
readme_directory = /usr/share/doc/postfix-2.10.1/README_FILES

relay_domains = mysql:/etc/postfix/mysql/relay_domains.cf
virtual_alias_maps = mysql:/etc/postfix/mysql/virtual_alias_maps.cf,
 mysql:/etc/postfix/mysql/virtual_alias_domain_maps.cf
virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual_mailbox_domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual_mailbox_maps.cf

smtpd_discard_ehlo_keywords = etrn, silent-discard
smtpd_forbidden_commands = CONNECT GET POST
broken_sasl_auth_clients = yes
smtpd_delay_reject = yes
smtpd_helo_required = yes
smtp_always_send_ehlo = yes
disable_vrfy_command = yes

smtpd_helo_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_non_fqdn_helo_hostname,
 reject_invalid_helo_hostname

smtpd_data_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_unauth_pipelining,
 reject_multi_recipient_bounce,

smtpd_sender_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_non_fqdn_sender,
 reject_unknown_sender_domain

smtpd_recipient_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_non_fqdn_recipient,
 reject_unknown_recipient_domain,
 reject_multi_recipient_bounce,
 reject_unauth_destination,

smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtpd_tls_security_level = may
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtp_tls_session_cache_database = btree:$data_directory/smtp_tls_session_cache
smtpd_tls_key_file = /etc/postfix/certs/key.pem
smtpd_tls_cert_file = /etc/postfix/certs/cert.pem
tls_random_source = dev:/dev/urandom
smtpd_tls_mandatory_ciphers = low
smtpd_tls_ciphers = low
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3
smtp_tls_mandatory_protocols  = !SSLv2,!SSLv3
smtp_tls_ciphers = low
smtp_tls_mandatory_ciphers = low
smtp_tls_protocols = !SSLv2,!SSLv3
smtp_tls_policy_maps = hash:/etc/postfix/tls_policy_maps
# фиксировать в логе имена серверов, выдающих сообщение STARTTLS, поддержка TLS для которых не включена
smtp_tls_note_starttls_offer = yes

# Ограничение максимального размера письма в байтах
message_size_limit = 20000000
smtpd_soft_error_limit = 10
smtpd_hard_error_limit = 15
smtpd_error_sleep_time = 20
anvil_rate_time_unit = 60s
smtpd_client_connection_count_limit = 20
smtpd_client_connection_rate_limit = 30
smtpd_client_message_rate_limit = 30
smtpd_client_event_limit_exceptions = 127.0.0.0/8
smtpd_client_connection_limit_exceptions = 127.0.0.0/8

maximal_queue_lifetime = 1d
bounce_queue_lifetime = 1d

smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/dovecot-auth

# Директория для хранения почты
virtual_mailbox_base = /mnt/mail
virtual_minimum_uid = 1000
virtual_uid_maps = static:1000
virtual_gid_maps = static:1000
virtual_transport = dovecot
dovecot_destination_recipient_limit = 1

sender_bcc_maps = hash:/etc/postfix/sender_bcc_maps
recipient_bcc_maps = hash:/etc/postfix/recipient_bcc_maps

compatibility_level=2

меняем значения на свои и сохраняем

Создаем папку для файлов с конфигурацией подключения к mysql и сами файлы подключения.

# mkdir /etc/postfix/mysql && cd /etc/postfix/mysql

# vi relay_domains.cf

hosts = localhost
user = postfix
password = 123
dbname = postfix
query = SELECT domain FROM domain WHERE domain='%s' and backupmx = '1'

# vi  virtual_alias_domain_maps.cf

hosts = localhost
user = postfix
password = 123
dbname = postfix
query = SELECT goto FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d' and alias.address = CONCAT('%u', '@', alias_domain.target_domain) AND alias.active = 1

# vi virtual_alias_maps.cf

hosts = localhost
user = postfix
password = 123
dbname = postfix
query = SELECT goto FROM alias WHERE address='%s' AND active = '1'

# vi virtual_mailbox_domains.cf

hosts = localhost
user = postfix
password = 123
dbname = postfix
query = SELECT domain FROM domain WHERE domain='%s' AND backupmx = '0' AND active = '1'

# vi virtual_mailbox_maps.cf

hosts = localhost
user = postfix
password = 123
dbname = postfix
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = '1'

Послесоздания всех этих файлов

# vi /etc/postfix/tls_policy_maps

93.175.56.122		none
77.221.87.91		encrypt protocols=TLSv1

# postmap /etc/postfix/tls_policy_maps

Продолжаем настройку почтового сервера postfix. Редактируем файл /etc/postfix/master.cf. Нам надо добавить строки, касающиеся настройки Submission для того, чтобы почтовый сервер работал на 587 порту. Смартфоны очень часто при настройке используют этот порт по-умолчанию, где-то даже без возможности изменить эту настройку. Приводим секцию, отвечающую за эту работу к следующему виду.


submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  
smtps inet n - n - - smtpd
 -o syslog_name=postfix/smtps
 -o smtpd_tls_wrappermode=yes
 -o smtpd_sasl_auth_enable=yes
 -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
 -o smtpd_relay_restrictions=permit_mynetworks,permit_sasl_authenticated,defer_unauth_destination
 -o milter_macro_daemon_name=ORIGINATING
 
В этот же файл добавляем еще одну настройку, которая будет указывать postfix, что доставкой почты у нас будет заниматься dovecot, который мы настроим следом. Добавляем в master.cf в самый конец.


dovecot unix - n n - - pipe
 flags=DRhu user=vmail:vmail argv=/usr/libexec/dovecot/deliver -f ${sender} -d ${recipient}
 
Сгенерируем самоподписанные ssl сертификаты для нашего почтового сервера. Позже отдельным пунктом я расскажу как использовать полноценные сертификаты. Они не всем нужны, поэтому показываю быструю настройку postfix на использование своих сертификатов, которые уже указаны в конфиге postfix.

Создаем директорию и сами сертификаты:

# mkdir /etc/postfix/certs
# openssl req -new -x509 -days 3650 -nodes -out /etc/postfix/certs/cert.pem -keyout /etc/postfix/certs/key.pem

Создадим файлы для информации о ящиках, куда будет собираться вся входящая и исходящая почта.

# mcedit /etc/postfix/recipient_bcc_maps

@domain.az all_in@domain.az

# mcedit /etc/postfix/sender_bcc_maps

@domain.az all_out@domain.az

Создаем индексированные базы данных из этих файлов. Это нужно делать каждый раз, после изменения.

# postmap /etc/postfix/recipient_bcc_maps /etc/postfix/sender_bcc_maps


Настройка dovecot.

# dnf install dovecot dovecot-mysql dovecot-pigeonhole

Изначально конфиг dovecot разбит на отдельные сегменты и лежат они в директории /etc/dovecot/conf.d. Каждый файл — отдельный функционал. Мне не нравится прыгать по файлам, поэтому я храню все в едином общем файле конфигурации /etc/dovecot/dovecot.conf. С ним мы и будем работать. Обращаю внимание, что это только вопрос удобства. Можете оставить все файлы отдельности, если вам так привычнее. Приводим конфиг к следующему виду.

listen = *

mail_plugins = mailbox_alias acl
protocols = imap pop3 sieve lmtp

mail_uid = 1000
mail_gid = 1000

first_valid_uid = 1000
last_valid_uid = 1000

auth_verbose = yes
log_path = /var/log/dovecot/main.log
info_log_path = /var/log/dovecot/info.log
debug_log_path = /var/log/dovecot/debug.log

#ssl_protocols = !SSLv3
#ssl = required
ssl_min_protocol = SSLv3
verbose_ssl = yes
ssl_cert = </etc/postfix/certs/cert.pem
ssl_key = </etc/postfix/certs/key.pem

ssl_cipher_list = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
ssl_prefer_server_ciphers = yes

disable_plaintext_auth = no

mail_location = maildir:/mnt/mail/%d/%u/

auth_default_realm = kirushin-vladimir.ru

auth_mechanisms = PLAIN LOGIN

service auth {
 unix_listener /var/spool/postfix/private/dovecot-auth {
 user = postfix
 group = postfix
 mode = 0666
 }
unix_listener auth-master {
 user = vmail
 group = vmail
 mode = 0666
 }

unix_listener auth-userdb {
 user = vmail
 group = vmail
 mode = 0660
 }
}

service lmtp {
 unix_listener /var/spool/postfix/private/dovecot-lmtp {
 user = postfix
 group = postfix
 mode = 0600
 }

 inet_listener lmtp {
 address = 127.0.0.1
 port = 24
 }
}

userdb {
 args = /etc/dovecot/dovecot-mysql.conf
 driver = sql
 }

passdb {
 args = /etc/dovecot/dovecot-mysql.conf
 driver = sql
 }

auth_master_user_separator = *
 
plugin {
 auth_socket_path = /var/run/dovecot/auth-master

 acl = vfile
 acl_shared_dict = file:/mnt/mail/shared-folders/shared-mailboxes.db
 sieve_dir = ~/.sieve/
 mailbox_alias_old = Sent
 mailbox_alias_new = Sent Messages
 mailbox_alias_old2 = Sent
 mailbox_alias_new2 = Sent Items
}

protocol lda {
 mail_plugins = $mail_plugins sieve
 auth_socket_path = /var/run/dovecot/auth-master
 deliver_log_format = mail from %f: msgid=%m %$
 log_path = /var/log/dovecot/lda-errors.log
 info_log_path = /var/log/dovecot/lda-deliver.log
 lda_mailbox_autocreate = yes
 lda_mailbox_autosubscribe = yes
# postmaster_address = root
}

protocol lmtp {
 info_log_path = /var/log/dovecot/lmtp.log
 mail_plugins = quota sieve
 postmaster_address = postmaster
 lmtp_save_to_detail_mailbox = yes
 recipient_delimiter = +
}

protocol imap {
 mail_plugins = $mail_plugins imap_acl
 imap_client_workarounds = tb-extra-mailbox-sep
 mail_max_userip_connections = 30
}

protocol pop3 {
 mail_plugins = $mail_plugins
 pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
 pop3_uidl_format = %08Xu%08Xv
 mail_max_userip_connections = 30
}

service imap-login {
 service_count = 1
 process_limit = 500
 }

service pop3-login {
 service_count = 1
 }

service managesieve-login {
 inet_listener sieve {
 port = 4190
 }
}

service stats {
    unix_listener stats-reader {
        user = vmail
        group = vmail
        mode = 0660
    }

    unix_listener stats-writer {
        user = vmail
        group = vmail
        mode = 0660
    }
}

namespace {
 type = private
 separator = /
 prefix =
 inbox = yes

 mailbox Sent {
 auto = subscribe
 special_use = \Sent
 }
 mailbox "Sent Messages" {
 auto = no
 special_use = \Sent
 }
 mailbox "Sent Items" {
 auto = no
 special_use = \Sent
 }
 mailbox Drafts {
 auto = subscribe
 special_use = \Drafts
 }
 mailbox Trash {
 auto = subscribe
 special_use = \Trash
 }
 mailbox "Deleted Messages" {
 auto = no
 special_use = \Trash
 }
 mailbox Junk {
 auto = subscribe
 special_use = \Junk
 }
 mailbox Spam {
 auto = no
 special_use = \Junk
 }
 mailbox "Junk E-mail" {
 auto = no
 special_use = \Junk
 }
 mailbox Archive {
 auto = no
 special_use = \Archive
 }
 mailbox Archives {
 auto = no
 special_use = \Archive
 }
}

namespace {
 type = shared
 separator = /
 prefix = Shared/%%u/
 location = maildir:%%h:INDEX=%h/shared/%%u
 subscriptions = yes
 list = children
}

Создаем группу и пользователя с указанными в конфиге uid 1001. Если у вас уже занят этот uid, то везде замените его на другой или удалите пользователя с uid 1001, если он вам не нужен.

# groupadd  -g 1001 vmail
# useradd -d /mnt/mail/ -g 1001 -u 1001 vmail
# chown vmail. /mnt/mail

Создаем конфигурационные файлы для доступа к mysql базе.

# vi /etc/dovecot/dovecot-mysql.conf

driver = mysql
default_pass_scheme = CRYPT
connect = host=127.0.0.1 dbname=postfix user=postfix password=123
user_query = SELECT '/mnt/mail/%d/%u' as home, 'maildir:/mnt/mail/%d/%u' as mail, 1001 AS uid, 1001 AS gid, concat('*:bytes=', quota) AS quota_rule FROM mailbox WHERE username = '%u' AND active = '1'
password_query = SELECT username as user, password, '/mnt/mail/%d/%u' as userdb_home, 'maildir:/mnt/mail/%d/%u' as userdb_mail, 1001 as userdb_uid, 1001 as userdb_gid, concat('*:bytes=', quota) AS userdb_quota_rule FROM mailbox WHERE username = '%u' AND active = '1'

Создадим директорию и файлы для логов.

# mkdir /var/log/dovecot
# cd /var/log/dovecot && touch main.log info.log debug.log lda-errors.log lda-deliver.log lmtp.log
# chown -R vmail:dovecot /var/log/dovecot

Создаем служебную папку для плагина acl.


# mkdir /mnt/mail/shared-folders
# chown -R vmail. /mnt/mail

На этом основная настройка почтового сервера на базе postfix и dovecot завершена. Можно запускать службы и проверять работу системы.

# systemctl restart postfix
# systemctl start dovecot
# systemctl enable postfix
# systemctl enable dovecot

Установка web интерфейса roundcube

Установим и настроим самый популярный web интерфейс для postfix — roundcube

# wget https://github.com/roundcube/roundcubemail/releases/download/1.4.9/roundcubemail-1.4.9-complete.tar.gz

Распаковываем и перемещаем на веб-сервер.


