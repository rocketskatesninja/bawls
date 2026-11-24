<?php

namespace App\Services;

/**
 * What a probe is after, in plain English, for the overview's weekly digest
 * of requests no attack pattern caught. A catalog of well-known probe
 * families, matched on the request's method, path and query; anything it
 * doesn't know gets a best guess from the request's shape, marked as one.
 * Offline: nothing about a request leaves the server to be explained.
 *
 * Some families here are ones the sensors now label themselves (.env hunts,
 * phpunit, ThinkPHP, ...: once a probe from the digest is added to
 * sensors/signatures.py it stops appearing there). They stay on purpose:
 * events recorded before the pattern existed still show in the digest for a
 * week, and a console may be newer than the sensors feeding it.
 */
class ProbeCatalog
{
    /**
     * Probe families, most specific first: [pattern, title, explanation]. A
     * pattern is matched against the lowercased "path?query"; %s in the
     * explanation is replaced with the pattern's first captured group.
     *
     * @var list<array{0: string, 1: string, 2: string}>
     */
    private const FAMILIES = [
        // AI tooling
        ['#/(\.claude|\.cursor|\.llm|\.config/llm|\.codeium|\.continue|\.aider)(/|\.|$)#', 'AI coding-agent config', 'Looks for an AI coding assistant\'s settings left in the web root (Claude Code, Cursor and the like). They can hold API keys and the addresses of the tools the agent uses.'],
        ['#^/(api/)?mcp/?$|^/sse/?$#', 'Open MCP server', 'Looks for a Model Context Protocol server, the way AI agents reach tools. One left open without a login lets anyone use its tools.'],
        ['#^/api/(tags|generate|chat|pull|ps|show)$#', 'Ollama', 'Probes for an Ollama server, which runs AI models. An exposed one gets used for free compute, or to pull and run models of the attacker\'s choosing.'],
        ['#^/v1/(models|chat/completions|completions|embeddings)#', 'OpenAI-style API', 'Looks for an OpenAI-compatible API (a proxy or a self-hosted model). An open one gives free use of a paid AI service, billed to its owner.'],

        // Secrets and settings left in the web root
        ['#/\.env([._-][a-z0-9._-]*)?$|[?&][a-z_]*=[./]*\.env#', 'Environment file (.env)', 'Looks for a .env file: the settings file of Laravel, Node and many other apps, holding database passwords, mail logins and API keys.'],
        ['#/\.git(/|$)|/\.git-credentials$|/\.gitconfig$#', 'Exposed Git repository', 'Looks for a site deployed with its .git folder still public. From it the whole source code and its history can be downloaded, secrets included.'],
        ['#/\.(svn|hg|bzr)(/|$)#', 'Exposed version control', 'Looks for a Subversion, Mercurial or Bazaar folder left public, which gives away the site\'s source code.'],
        ['#/\.aws/#', 'AWS credentials', 'Looks for an AWS credentials file: keys that can control the owner\'s Amazon cloud account.'],
        ['#/\.ssh/|/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|/authorized_keys$|/known_hosts$#', 'SSH keys', 'Looks for an SSH private key left on the web server. One would let the attacker log in wherever that key is trusted.'],
        ['#/\.(npmrc|yarnrc(\.yml)?)$#', 'npm token', 'Looks for an .npmrc file, which can hold the token for publishing JavaScript packages: a way into other people\'s software.'],
        ['#/\.pypirc$#', 'PyPI token', 'Looks for a .pypirc file, which holds the login for publishing Python packages.'],
        ['#/\.netrc$#', 'Saved logins (.netrc)', 'Looks for a .netrc file: saved usernames and passwords for FTP and HTTP servers.'],
        ['#/\.dockercfg$|/\.docker/config\.json$#', 'Docker registry login', 'Looks for a Docker config holding container-registry passwords.'],
        ['#/docker-compose[^/]*\.ya?ml$|/dockerfile$#', 'Docker Compose file', 'Looks for a Docker Compose file, which lists a site\'s services and often their passwords.'],
        ['#/\.(s3cfg|boto|passwd-s3fs)$#', 'S3 tool credentials', 'Looks for the config of an Amazon S3 command-line tool, which holds storage access keys.'],
        ['#/\.azure/#', 'Azure credentials', 'Looks for an Azure command-line folder with sign-in tokens for a Microsoft cloud account.'],
        ['#/\.config/gcloud|/\.gcloud/|service[_-]?account[^/]*\.json$#', 'Google Cloud credentials', 'Looks for Google Cloud sign-in files or a service-account key.'],
        ['#/\.kube/|/kubeconfig#', 'Kubernetes config', 'Looks for a kubeconfig file, which carries admin access to a Kubernetes cluster.'],
        ['#/\.(travis|gitlab-ci|drone)\.ya?ml$|/\.github/workflows|/\.circleci/|/bitbucket-pipelines\.yml$|/jenkinsfile$#', 'CI pipeline config', 'Looks for a build pipeline\'s config, which shows how the site is deployed and sometimes holds deploy secrets.'],
        ['#/wp-config\.php#', 'WordPress config', 'Looks for wp-config.php or a backup copy of it (.bak, ~, .old). Served as text, a copy gives away the WordPress database password.'],
        ['#/configuration\.php#', 'Joomla config', 'Looks for Joomla\'s configuration.php (or a backup copy), which holds the database password.'],
        ['#/sites/default/(settings|files)#', 'Drupal settings', 'Looks for Drupal\'s settings file or its uploads folder.'],
        ['#/localsettings\.php#', 'MediaWiki config', 'Looks for MediaWiki\'s LocalSettings.php, which holds the database password and secret keys.'],
        ['#/app/etc/(env|local)\.(php|xml)#', 'Magento config', 'Looks for Magento\'s settings file, with the database password and encryption key.'],
        ['#/parameters\.ya?ml$#', 'Symfony parameters', 'Looks for a Symfony parameters file, with database passwords and the app secret.'],
        ['#/appsettings[^/]*\.json$|/web\.config$#', '.NET settings', 'Looks for an ASP.NET appsettings.json or web.config: connection strings and secret keys.'],
        ['#/application(-[a-z]+)?\.(properties|ya?ml)$|/bootstrap\.ya?ml$#', 'Spring Boot settings', 'Looks for a Spring Boot application.properties or .yml, with database and service passwords.'],
        ['#/(local_)?settings\.py$#', 'Django settings', 'Looks for a Django settings file, with the database password and the SECRET_KEY that signs sessions.'],
        ['#/\.htpasswd$#', 'Password file (.htpasswd)', 'Looks for an Apache password file: usernames and password hashes to crack.'],
        ['#/(database|secrets?|credentials|config|settings|conf)\.(ya?ml|json|ini|toml|php|inc|js|xml|txt)$#', 'Config or secrets file', 'Looks for a settings file by a common name, hoping it holds passwords or keys and is served as plain text.'],
        ['#^/(env|environment|debug/vars|server-info)/?$#', 'Environment dump', 'Looks for a page that prints the server\'s environment variables (Spring\'s /env, Go\'s /debug/vars and the like), which often hold secrets.'],
        ['#/(php_?info|info|phpversion|pi|i)\.php$#', 'phpinfo page', 'Looks for a page left over from setup that prints PHP\'s whole configuration, often including environment variables and secrets.'],
        ['#/(storage/logs|logs?)/[^/]*\.log$|/(error|debug|access|laravel|php_errors?)\.log$|/error_log$#', 'Log file', 'Looks for a log file, which can leak stack traces, file paths, tokens and visitors\' data.'],
        ['#\.(sql|sql\.gz|dump|sqlite3?|bak|old|orig|backup|zip|tar|tar\.gz|tgz|gz|7z|rar)$|/backups?(/|$)#', 'Backup or database dump', 'Looks for a backup of the site or its database left in the web root: everything in one download.'],
        ['#/\.ds_store$#', '.DS_Store', 'Looks for a macOS folder index uploaded with a site by mistake. It lists the names of the files in that folder, a map for further guessing.'],
        ['#/\.(vscode|idea)/#', 'Editor config', 'Looks for a code editor\'s project folder. VS Code\'s sftp.json, for one, holds the password used to upload the site.'],
        ['#/\.(bash|zsh|mysql|psql|python)_history$|/\.history$#', 'Shell history', 'Looks for a command history file, which records what the server\'s users typed, passwords sometimes included.'],
        ['#/(env|config|settings|runtime-config|app-config|main|bundle)(\.[a-z0-9]+)?\.js$#', 'Front-end config', 'Looks for a JavaScript settings file, where single-page apps often bake in API keys and backend addresses.'],

        // APIs and their maps
        ['#/(swagger(-ui)?|api-docs|openapi)([./-]|$)|/v[23]/api-docs#', 'API documentation', 'Looks for Swagger/OpenAPI docs: a map of every API endpoint and its parameters.'],
        ['#/graphi?ql#', 'GraphQL', 'Probes a GraphQL endpoint, often with an introspection query that lists everything it serves, or a query listing users (WordPress\'s WPGraphQL).'],

        // WordPress
        ['#/wp-json|[?&]rest_route=#', 'WordPress REST API', 'Uses WordPress\'s REST API, most often to list the site\'s usernames for password guessing.'],
        ['#[?&]author=\d#', 'WordPress author lookup', 'Asks WordPress for the author with that number, which answers with their username: a way to collect logins to guess passwords for.'],
        ['#/xmlrpc\.php#', 'WordPress XML-RPC', 'Calls WordPress\'s XML-RPC API, which can try hundreds of passwords in a single request (system.multicall) and is used for pingback floods.'],
        ['#/wp-login\.php|/wp-admin#', 'WordPress login', 'Looks for the WordPress sign-in page, to try passwords on it.'],
        ['#/wp-content/plugins/([^/?]+)#', 'WordPress plugin', 'Checks whether the WordPress plugin "%s" is installed, usually because a version of it has a known hole.'],
        ['#/wp-content/themes/([^/?]+)#', 'WordPress theme', 'Checks whether the WordPress theme "%s" is installed, usually because a version of it has a known hole.'],
        ['#/wp-includes/|/wlwmanifest\.xml#', 'WordPress check', 'Fetches a file every WordPress has, to learn whether the site runs WordPress, and which version.'],
        ['#/(readme|license|changelog)\.(html?|txt|md)$#', 'Version fingerprinting', 'Fetches a readme or changelog that many apps ship, which gives away the software and its version.'],
        ['#/(comments/)?feed(/(atom|json|rss2?))?/?$|/rss/?$#', 'Feed', 'Fetches an RSS or Atom feed. Normal for feed readers, and used by scanners to confirm WordPress.'],
        ['#/(sitemap_index|wp-sitemap|post-sitemap|page-sitemap|sitemap)[^/]*\.xml$#', 'Sitemap', 'Fetches a sitemap to find pages. sitemap_index.xml in particular is the Yoast plugin\'s, so it doubles as a WordPress check.'],

        // Admin panels and databases
        ['#/(phpmyadmin|pma|myadmin|mysqladmin|dbadmin|phpmy|sqladmin)#', 'phpMyAdmin', 'Looks for phpMyAdmin, a web front end to MySQL, to try default and weak database passwords.'],
        ['#/adminer[^/]*(\.php)?$#', 'Adminer', 'Looks for Adminer, a one-file database tool. Left online, it is a direct way into the database.'],
        ['#/administrator(/|$)#', 'Joomla admin', 'Looks for the Joomla administrator sign-in.'],
        ['#^/user/(login|register|password)#', 'Drupal sign-in', 'Looks for Drupal\'s sign-in or registration page.'],
        ['#^/(cpanel|whm|webmail|2082|2083|2086|2087)(/|$)#', 'cPanel / WHM', 'Looks for cPanel or WHM, the hosting control panels, to try passwords on them.'],
        ['#/(manager/html|host-manager)#', 'Tomcat Manager', 'Looks for Apache Tomcat\'s manager. With a default password it lets anyone upload an app, and so run code on the server.'],
        ['#/jenkins|^/script$|/jnlpjars|/computer/#', 'Jenkins', 'Looks for a Jenkins build server. An open one runs whatever script it is given.'],
        ['#^/console(/|$)|/wls-wsat/|/_async/#', 'Admin console (WebLogic)', 'Looks for an application server\'s admin console. Oracle WebLogic serves one at /console, and it has had several remote-code holes.'],
        ['#/solr(/|$)#', 'Apache Solr', 'Looks for an Apache Solr search admin, which has had remote-code and file-reading holes.'],
        ['#/actuator#', 'Spring Boot Actuator', 'Looks for Spring Boot\'s actuator endpoints, which can expose environment variables, memory dumps with secrets, or a way to run code.'],
        ['#/jolokia#', 'Jolokia (JMX)', 'Looks for Jolokia, which exposes a Java app\'s management controls over HTTP.'],
        ['#/telescope#', 'Laravel Telescope', 'Looks for Laravel Telescope, a debugging dashboard that, left public, shows every request, query and exception, secrets included.'],
        ['#/_ignition|/_debugbar|/horizon(/|$)#', 'Laravel debug tools', 'Looks for Laravel\'s debug tools (Ignition, Debugbar, Horizon). Ignition had a remote-code hole (CVE-2021-3129).'],
        ['#/debug/default/view#', 'Yii debug panel', 'Looks for the Yii framework\'s debug panel left on in production, which shows settings, requests and database queries.'],
        ['#/_profiler|/app_dev\.php#', 'Symfony profiler', 'Looks for Symfony\'s profiler, which shows requests, settings and phpinfo when left on in production.'],
        ['#/(elmah|trace)\.axd#', 'ASP.NET error log', 'Looks for ASP.NET\'s error log (ELMAH) or trace page, which can show other users\' requests and session cookies.'],
        ['#^/(owa|ecp|ews|mapi|rpc|autodiscover)(/|$)|/autodiscover\.xml#', 'Microsoft Exchange', 'Looks for Exchange webmail or its services, the target of ProxyShell, ProxyLogon and password spraying.'],
        ['#^/remote/(login|fgt_lang|logincheck)#', 'Fortinet VPN', 'Looks for a Fortinet FortiGate SSL VPN, which has had several holes used to break into company networks.'],
        ['#/global-protect|/ssl-vpn/#', 'Palo Alto VPN', 'Looks for a Palo Alto GlobalProtect VPN portal.'],
        ['#/dana-(na|ws)/#', 'Ivanti VPN', 'Looks for an Ivanti (Pulse Secure) Connect Secure VPN, a frequent target of mass exploitation.'],
        ['#/\+(cscoe|webvpn)\+#', 'Cisco VPN', 'Looks for a Cisco ASA WebVPN portal.'],
        ['#/vpn/index\.html|/logon/logonpoint|/nf/auth|/citrix#', 'Citrix gateway', 'Looks for a Citrix NetScaler / ADC gateway, the target of the "Citrix Bleed" attacks.'],
        ['#/tmui/#', 'F5 BIG-IP', 'Looks for the F5 BIG-IP management page, which had a remote-code hole (CVE-2020-5902).'],
        ['#/boaform#', 'Fiber router (Boa)', 'Targets fiber routers running the Boa web server, whose admin form botnets use to run commands.'],
        ['#/hnap1#', 'D-Link HNAP', 'Targets the HNAP interface of D-Link routers, used by botnets to take them over.'],
        ['#/cgi-bin/luci#', 'OpenWrt LuCI', 'Looks for the admin page of an OpenWrt router.'],
        ['#/gponform#', 'GPON router', 'Targets GPON home routers with a known login bypass and command injection, a botnet favourite.'],
        ['#/goform/#', 'Router form handler', 'Targets a router\'s form handler (Tenda and others), where command injection holes are common.'],
        ['#/ctrlt/deviceupgrade#', 'Huawei router', 'Targets Huawei HG532 routers with the hole Mirai-style botnets use to spread.'],
        ['#/picsdesc\.xml|^/ud/#', 'Realtek UPnP', 'Targets routers built on Realtek\'s chips through their UPnP service, a long-running botnet hole.'],
        ['#/setup\.cgi#', 'Netgear router', 'Targets old Netgear routers with a command-injection hole used by botnets.'],
        ['#/(tm|hnd)unblock\.cgi#', 'Linksys router', 'Targets old Linksys routers with a command-injection hole.'],
        ['#/(php-?cgi|cgi-bin/php)#', 'PHP-CGI', 'Targets PHP running as CGI on Windows, which can be made to run code (CVE-2024-4577).'],
        ['#/cgi-bin/#', 'CGI script', 'Looks for an old CGI script, the classic way in through Shellshock or Apache\'s path holes.'],
        ['#/geoserver#', 'GeoServer', 'Looks for GeoServer, a map server with a remote-code hole (CVE-2024-36401).'],
        ['#/developmentserver/metadatauploader#', 'SAP NetWeaver', 'Targets SAP NetWeaver Visual Composer, which let anyone upload and run code (CVE-2025-31324).'],
        ['#/vendor/phpunit#', 'PHPUnit', 'Looks for the testing library PHPUnit left in a site\'s vendor folder, whose eval-stdin.php runs any code it is sent.'],
        ['#think\\\\app|/index\.php\?s=#', 'ThinkPHP', 'Targets ThinkPHP, a PHP framework with a remote-code hole that botnets still probe for.'],
        ['#/struts|\.action$|\.do$#', 'Java web app (Struts)', 'Looks for a Java web app\'s .action or .do pages, the shape of Apache Struts apps and their remote-code holes.'],
        ['#/ws/v1/cluster/apps#', 'Hadoop YARN', 'Targets an open Hadoop YARN API, which runs any job it is given; cryptominers love it.'],
        ['#/(jmx-console|invoker/|web-console)#', 'JBoss', 'Looks for JBoss\'s management consoles, open to remote code on old versions.'],
        ['#/cfide/#', 'ColdFusion', 'Looks for Adobe ColdFusion\'s admin folder.'],
        ['#/api/jsonws#', 'Liferay', 'Looks for Liferay\'s JSON web services, which had a remote-code hole.'],
        ['#/(confluence|jira)(/|$)|/login\.action$|/rest/api/latest/serverinfo#', 'Atlassian Confluence / Jira', 'Looks for Confluence or Jira, which have had several remote-code holes.'],
        ['#/_vti_(bin|pvt|inf)|/_layouts/#', 'SharePoint / FrontPage', 'Looks for SharePoint or FrontPage extensions.'],
        ['#/crx/|/bin/querybuilder|/libs/granite#', 'Adobe Experience Manager', 'Looks for Adobe Experience Manager\'s admin and query tools.'],
        ['#/api/session/properties#', 'Metabase', 'Targets Metabase, which had a pre-login remote-code hole (CVE-2023-38646).'],
        ['#/nacos#', 'Nacos', 'Looks for Alibaba Nacos, a config server with a well-known login bypass.'],
        ['#/druid/#', 'Druid monitor', 'Looks for Alibaba Druid\'s monitoring page, which shows database queries and sessions.'],
        ['#/(ueditor|fckeditor|ckfinder|kindeditor)#', 'Web editor uploader', 'Looks for a rich-text editor\'s file uploader, a common way to upload a webshell.'],
        ['#/(elfinder|filemanager|kcfinder|tinyfilemanager)|/upload(er)?\.php$#', 'File manager / uploader', 'Looks for a web file manager or upload script, to upload a webshell.'],
        ['#/(shell|cmd|wso|alfa[a-z0-9]*|c99|r57|b374k|marijuana|indoxploit|up|upl|x|xx|xxx|z|a|1|ok|tiny|fm|wp-l0gin)\.php$#', 'Webshell hunting', 'Looks for a backdoor (a webshell) by a common name, left by whoever broke into the site before. If one answered, the attacker would take it over.'],

        // Infrastructure
        ['#^/api/v1/(pods|namespaces|secrets|nodes)|^/apis/#', 'Kubernetes API', 'Looks for an open Kubernetes API, which would hand over the whole cluster.'],
        ['#^/v2/(_catalog)?/?$#', 'Docker registry', 'Asks a Docker registry for its list of images, to download them and look inside for secrets.'],
        ['#/containers/json|^/_ping$|^/v1\.\d+/(containers|version|info)#', 'Docker API', 'Looks for an open Docker Engine API: anyone who reaches it can start containers, which means root on the host.'],
        ['#/_(cat|cluster|search|all|nodes|mapping)(/|$)#', 'Elasticsearch', 'Looks for an open Elasticsearch database, to read or wipe its data.'],
        ['#/(grafana|kibana|zabbix|prometheus|nagios|netdata)(/|$)|/app/kibana#', 'Monitoring dashboard', 'Looks for a monitoring dashboard (Grafana, Kibana and the like), often left on default passwords.'],
        ['#^/metrics$#', 'Prometheus metrics', 'Fetches a Prometheus metrics page, which can reveal software versions and internal names.'],
        ['#/portainer|/api/endpoints#', 'Portainer', 'Looks for Portainer, a Docker admin panel; an unconfigured one can be claimed by whoever gets there first.'],
        ['#^/(api/)?(v\d+/)?(version|status|info|health|healthz|ping)/?$#', 'Version / status check', 'Asks an API for its version or health: a quick way to tell what software, and which version, runs here.'],
        ['#^/lander(/|$)#', 'Ad / phishing lander', '"lander" is the default page name of several ad-cloaking and phishing kits. Scanners check for one to find kits to hijack, or sites already compromised.'],

        // Ordinary crawler traffic
        ['#/\.well-known/security\.txt#', 'security.txt', 'Fetches the file that says how to report a security problem. Researchers and scanners both read it; usually harmless.'],
        ['#/\.well-known/(openid-configuration|oauth-authorization-server)#', 'OpenID / OAuth discovery', 'Asks whether this site runs an OpenID or OAuth sign-in service.'],
        ['#/\.well-known/acme-challenge#', 'Let\'s Encrypt check', 'A certificate authority checking a domain while issuing a certificate. Harmless.'],
        ['#^/(robots\.txt|sitemap\.xml|favicon\.ico|ads\.txt|app-ads\.txt|humans\.txt)$#', 'Standard file', 'A file well-behaved crawlers fetch from every site. Harmless on its own.'],
        ['#/cdn-cgi/#', 'Cloudflare check', 'Asks for a Cloudflare path, to learn whether the site sits behind Cloudflare.'],
        ['#[?&]xdebug_session(_start)?=#', 'Xdebug', 'Tries to start PHP\'s Xdebug debugger, which, left on, can be made to run code.'],
        ['#^/(login|signin|sign-in|log-in|admin|admin\.php|panel|dashboard|backend|manage|manager)(\.html?|\.php|\.aspx?|/)?$#', 'Login or admin page', 'Looks for a sign-in or admin page by a common name, to try passwords on it.'],
    ];

    /**
     * What the request is after: a known family, or a best guess from its shape.
     *
     * @return array{title: string, text: string, known: bool}
     */
    public function explain(string $method, string $path, ?string $query = null): array
    {
        $method = strtoupper($method);
        $target = strtolower($path.($query !== null && $query !== '' ? "?{$query}" : ''));

        if ($method === 'CONNECT' || preg_match('#^(https?://|[a-z0-9.-]+:\d+$)#', $target)) {
            return $this->known('Open proxy test', 'Tries to use the server as a proxy to reach another site. An open proxy would let the attacker hide behind this server\'s address.');
        }
        if (in_array($method, ['PROPFIND', 'PROPPATCH', 'MKCOL', 'MOVE', 'COPY', 'LOCK', 'UNLOCK'], true)) {
            return $this->known('WebDAV', 'Uses WebDAV, a way of managing files over HTTP, to see whether it can list or upload files here.');
        }
        if ($method === 'PUT') {
            return $this->known('Upload attempt', 'Tries to upload a file with PUT. Where that works, the next step is a webshell.');
        }
        if ($method === 'OPTIONS') {
            return $this->known('Methods check', 'Asks which HTTP methods the server allows: a first step before trying an upload or WebDAV.');
        }
        if (in_array($method, ['TRACE', 'TRACK'], true)) {
            return $this->known('TRACE check', 'Checks whether the server echoes requests back (TRACE), an old way to steal cookies.');
        }

        foreach (self::FAMILIES as [$pattern, $title, $text]) {
            if (preg_match($pattern, $target, $match)) {
                return $this->known($title, str_contains($text, '%s') ? sprintf($text, $match[1] ?? '') : $text);
            }
        }

        return $this->guess($method, strtolower($path), (string) $query);
    }

    /**
     * @return array{title: string, text: string, known: bool}
     */
    private function known(string $title, string $text): array
    {
        return ['title' => $title, 'text' => $text, 'known' => true];
    }

    /**
     * Not in the catalog: a best guess from the request's shape.
     *
     * @return array{title: string, text: string, known: bool}
     */
    private function guess(string $method, string $path, string $query): array
    {
        $guess = fn (string $title, string $text): array => ['title' => $title, 'text' => $text, 'known' => false];
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return match (true) {
            $method === 'POST' && $path === '/' => $guess('Blind exploit attempt', 'Posts data to the home page: usually an exploit for whatever software might be answering there, fired without checking first.'),
            $method === 'POST' => $guess('Blind exploit attempt', 'Sends data to a page that doesn\'t exist here: usually an exploit for software that lives at this path, fired without checking first.'),
            (bool) preg_match('#/\.[^/]+$#', $path) => $guess('Hidden file', 'Looks for a hidden file (a name starting with a dot), the kind that usually holds settings or credentials.'),
            in_array($extension, ['php', 'asp', 'aspx', 'jsp', 'cgi', 'pl', 'cfm'], true) => $guess('Script check', "Looks for a .{$extension} script by this name: a known-vulnerable tool, an admin page, or a webshell left by an earlier break-in."),
            in_array($extension, ['json', 'yml', 'yaml', 'xml', 'ini', 'conf', 'cfg', 'toml', 'properties', 'txt', 'log'], true) => $guess('File hunting', "Looks for a .{$extension} file that might hold settings, credentials or logs."),
            str_starts_with($path, '/api/') => $guess('API discovery', 'Probes for an API endpoint, to work out what software runs here or find one left open.'),
            $query !== '' => $guess('Parameter probe', 'Tries a parameter: usually the trigger of an exploit for some web app, or a check whether input is echoed back (for cross-site scripting).'),
            default => $guess('Wordlist scan', 'An unknown path. Most likely a scanner working through a wordlist, checking for an app, admin page or file that would tell it what runs here.'),
        };
    }
}
