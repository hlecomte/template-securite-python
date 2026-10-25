/*
    pattern.yar — Règles YARA pour l'analyse PAQUET PAR PAQUET

    Conçu pour _attack_warning(), qui scanne le contenu applicatif de chaque
    paquet (couche Raw) APRÈS décodage par unquote_plus().
    Exemple : "id=1%27+OR+1%3D1" est déjà devenu "id=1' OR 1=1".

    Règles :
      - pas de condition sur l'en-tête du fichier (uint32(0) == pcap)
      - pas de compteur entre paquets (#syn > 100…) : un paquet = un scan
      - motifs sur les DONNÉES, pas sur les en-têtes Ethernet/IP/TCP

    Les attaques réseau (scan de ports, ARP spoofing) se détectent par
    comptage sur l'ensemble de la capture : voir detection_reseau.yar.

    Champs meta lus par le script :
      description  -> "details" de l'alerte
      category     -> famille d'attaque
      severity     -> low / medium / high / critical
*/


/* ================================================================== */
/*  Contexte : le paquet est-il une requête HTTP ?                     */
/*  Limiter les règles web aux REQUÊTES évite les faux positifs dans   */
/*  les réponses (une page HTML légitime contient du <script>).        */
/* ================================================================== */

private rule HTTP_Request
{
    strings:
        // Pas de \S+ pour l'URL : après unquote_plus elle peut contenir des espaces
        $methode = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^\r\n]+ HTTP\/[0-9.]+\r?\n/

    condition:
        $methode at 0
}


/* ================================================================== */
/*  1. Injection SQL                                                   */
/* ================================================================== */

rule SQL_Injection
{
    meta:
        description = "Injection SQL : UNION SELECT, tautologie, requête empilée ou injection temporelle"
        category    = "SQL Injection"
        severity    = "high"

    strings:
        // Motifs forts : un seul suffit
        $union    = /union(\s|\/\*[^*]*\*\/)+(all(\s|\/\*[^*]*\*\/)+)?select\s/ nocase
        $stacked  = /;\s*(drop|truncate|alter)\s+table\s/ nocase
        $sleep    = /(sleep|pg_sleep)\s*\(\s*\d+\s*\)/ nocase
        $bench    = /benchmark\s*\(\s*\d+\s*,/ nocase
        $waitfor  = /waitfor\s+delay\s+'/ nocase
        $tauto    = /'\s*(or|and)\s+'?(\w+)'?\s*=\s*'?\w+/ nocase
        $tauto_n  = /\s(or|and)\s+\d+\s*=\s*\d+(\s|$|--|#|;)/ nocase
        $bypass   = /'\s*(--|#)(\s|&|$)/                       // admin'--  (fin de la valeur)

        // Motifs faibles : il en faut deux
        $schema   = "information_schema" nocase
        $comment  = /'\s*(--|#|\/\*)/
        $concat   = /(concat|group_concat|char)\s*\(/ nocase
        $version  = /@@version|version\s*\(\s*\)/ nocase

    condition:
        HTTP_Request and
        (
            any of ($union, $stacked, $sleep, $bench, $waitfor, $tauto, $tauto_n, $bypass) or
            2 of ($schema, $comment, $concat, $version)
        )
}


/* ================================================================== */
/*  2. Cross-Site Scripting (XSS)                                      */
/* ================================================================== */

rule XSS
{
    meta:
        description = "Cross-Site Scripting : balise ou gestionnaire d'événement JavaScript injecté dans une requête"
        category    = "XSS"
        severity    = "high"

    strings:
        $script   = /<\s*script[\s>\/]/ nocase
        $handler  = /<\s*(img|svg|body|iframe|input|video|details|a)\b[^>]*\son[a-z]+\s*=/ nocase
        $js_uri   = /(href|src|action)\s*=\s*["']?\s*javascript:/ nocase
        $js_param = /=\s*javascript:/ nocase
        $cookie   = /document\.(cookie|location|domain)/ nocase
        $iframe   = /<\s*iframe[^>]+src\s*=/ nocase

    condition:
        HTTP_Request and any of them
}


/* ================================================================== */
/*  3. Path traversal / inclusion de fichier local (LFI)               */
/* ================================================================== */

rule Path_Traversal
{
    meta:
        description = "Path traversal / LFI : remontée d'arborescence ou accès à un fichier système sensible"
        category    = "Path Traversal"
        severity    = "high"

    strings:
        $dotdot     = /(\.\.[\/\\]){2,}/
        $dotdot_enc = /(%2e%2e|\.\.)(%2f|%5c)/ nocase          // double encodage restant
        $passwd     = /\/etc\/(passwd|shadow|hosts|group)\b/
        $win        = /(boot\.ini|win\.ini|system32[\/\\])/ nocase
        $wrapper    = /(php|file|expect|zip|phar):\/\// nocase

    condition:
        HTTP_Request and any of them
}


/* ================================================================== */
/*  4. Injection de commandes système                                  */
/* ================================================================== */

rule Command_Injection
{
    meta:
        description = "Injection de commande : séparateur shell suivi d'une commande système"
        category    = "Command Injection"
        severity    = "critical"

    strings:
        // ;cat  |id  &&whoami  $(uname)  `wget ...`
        $chain  = /(;|\||&&|\$\(|`)\s*(cat|id|whoami|uname|ls|pwd|wget|curl|nc|ncat|bash|sh|ping|nslookup|rm|chmod|python3?|perl)(\s|$|;|\||\)|`)/
        $shell  = /\/bin\/(ba|z|da)?sh\b/
        $win    = /(cmd(\.exe)?\s*\/c|powershell(\.exe)?\s+-)/ nocase
        $revsh  = /\/dev\/tcp\/\d{1,3}(\.\d{1,3}){3}\/\d+/

    condition:
        HTTP_Request and any of them
}


/* ================================================================== */
/*  5. Log4Shell (CVE-2021-44228)                                      */
/*  Pas de condition HTTP_Request : la charge peut arriver dans        */
/*  n'importe quel protocole texte (en-tête HTTP, LDAP, SMTP…).        */
/* ================================================================== */

rule Log4Shell
{
    meta:
        description = "Exploitation Log4Shell : expression JNDI dans les données (CVE-2021-44228)"
        category    = "RCE"
        severity    = "critical"

    strings:
        $jndi    = /\$\{\s*jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|http|nis|corba)/ nocase
        $obfusc  = /\$\{[^}]{0,30}\$\{(lower|upper|env|sys|::-)/ nocase

    condition:
        any of them
}


/* ================================================================== */
/*  6. Upload de web shell / code PHP dans une requête                 */
/* ================================================================== */

rule Webshell_Upload
{
    meta:
        description = "Code PHP exécutable envoyé dans une requête (upload de web shell)"
        category    = "Web Shell"
        severity    = "critical"

    strings:
        $php_tag = /<\?(php|=)/ nocase
        $exec    = /(system|exec|shell_exec|passthru|popen|proc_open|assert|eval)\s*\(/ nocase
        $b64     = /base64_decode\s*\(/ nocase
        $input   = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/

    condition:
        HTTP_Request and $php_tag and ($exec or $b64 or $input)
}


/* ================================================================== */
/*  7. SSRF vers des services de métadonnées cloud                     */
/* ================================================================== */

rule SSRF_Metadata
{
    meta:
        description = "SSRF : requête qui cible un service interne de métadonnées cloud"
        category    = "SSRF"
        severity    = "high"

    strings:
        $aws    = "169.254.169.254"
        $gcp    = "metadata.google.internal" nocase
        $azure  = "169.254.169.254/metadata" nocase
        $local  = /=\s*(https?|gopher|dict):\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0)/ nocase

    condition:
        HTTP_Request and any of them
}


/* ================================================================== */
/*  8. Outil d'attaque ou scanner identifié par son User-Agent         */
/* ================================================================== */

rule Scanner_User_Agent
{
    meta:
        description = "Requête émise par un outil de scan ou d'attaque (User-Agent identifié)"
        category    = "Reconnaissance"
        severity    = "medium"

    strings:
        $ua = /\r\nUser-Agent:[^\r\n]*(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|ffuf|wfuzz|wpscan|acunetix|nessus|openvas|hydra|nuclei|w3af|burp)/ nocase

    condition:
        HTTP_Request and $ua
}


/* ================================================================== */
/*  9. Identifiants transmis en clair                                  */
/*  Pas une attaque en soi, mais une faiblesse exploitable par         */
/*  quiconque écoute le réseau (ex. après un ARP spoofing).            */
/* ================================================================== */

rule Cleartext_Credentials
{
    meta:
        description = "Identifiants transmis en clair (FTP, POP3, IMAP ou HTTP Basic)"
        category    = "Credentials"
        severity    = "low"

    strings:
        $ftp_pop = /^(PASS|USER) \S+\r?\n/                   // FTP et POP3
        $imap    = /^\S+ LOGIN \S+ \S+\r?\n/ nocase           // IMAP
        $basic   = /\r\nAuthorization:\s*Basic\s+[A-Za-z0-9+\/=]{4,}/ nocase

    condition:
        $ftp_pop at 0 or $imap at 0 or $basic
}
