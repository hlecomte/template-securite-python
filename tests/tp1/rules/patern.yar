/*
    Règles YARA de détection réseau sur fichiers de capture (.pcap / .pcapng)

    Hypothèses :
      - capture Ethernet (linktype 1)
      - IPv4 sans options (IHL = 5, octet 0x45)

    Utilisation :
      yara -s detection_reseau.yar capture.pcap
*/


/* ------------------------------------------------------------------ */
/*  Prérequis : le fichier analysé est une capture pcap / pcapng       */
/* ------------------------------------------------------------------ */

private rule Is_Pcap
{
    meta:
        description = "Fichier de capture pcap (micro/nanosecondes, LE/BE) ou pcapng"

    condition:
        uint32(0) == 0xA1B2C3D4 or   // pcap little-endian
        uint32(0) == 0xD4C3B2A1 or   // pcap big-endian
        uint32(0) == 0xA1B23C4D or   // pcap nanosecondes little-endian
        uint32(0) == 0x4D3CB2A1 or   // pcap nanosecondes big-endian
        uint32(0) == 0x0A0D0D0A      // pcapng
}


/* ------------------------------------------------------------------ */
/*  1. ARP Spoofing                                                    */
/* ------------------------------------------------------------------ */

rule ARP_Spoofing_Unsolicited_Replies
{
    meta:
        description = "Nombre anormal de réponses ARP par rapport aux requêtes (réponses non sollicitées)"
        category    = "ARP Spoofing"
        severity    = "high"

    strings:
        // EtherType ARP | Ethernet | IPv4 | tailles 6/4 | opcode
        $arp_request = { 08 06 00 01 08 00 06 04 00 01 }
        $arp_reply   = { 08 06 00 01 08 00 06 04 00 02 }

    condition:
        Is_Pcap and
        #arp_reply > 10 and
        #arp_reply > 2 * #arp_request
}

rule ARP_Spoofing_Gratuitous_Broadcast
{
    meta:
        description = "Réponses ARP envoyées en broadcast (ARP gratuit répété, typique d'un empoisonnement de cache)"
        category    = "ARP Spoofing"
        severity    = "high"

    strings:
        // MAC destination broadcast | MAC source | EtherType ARP ... opcode reply
        $gratuitous_reply = { FF FF FF FF FF FF [6] 08 06 00 01 08 00 06 04 00 02 }

    condition:
        Is_Pcap and #gratuitous_reply > 5
}


/* ------------------------------------------------------------------ */
/*  2. Scan de ports                                                   */
/*  Trame : EtherType 0x0800 | IP 0x45 | ... protocole 0x06 (TCP)      */
/*          puis 23 octets jusqu'aux flags TCP                          */
/* ------------------------------------------------------------------ */

rule Port_Scan_SYN
{
    meta:
        description = "Grand nombre de SYN avec beaucoup de RST/ACK en retour (scan SYN / connect)"
        category    = "Port Scan"
        severity    = "medium"

    strings:
        $syn     = { 08 00 45 [8] 06 [23] 02 }   // flags = SYN
        $rst_ack = { 08 00 45 [8] 06 [23] 14 }   // flags = RST + ACK (port fermé)

    condition:
        Is_Pcap and
        #syn > 100 and
        #rst_ack > 50
}

rule Port_Scan_Stealth
{
    meta:
        description = "Paquets TCP aux combinaisons de flags anormales (scans Xmas, NULL, FIN d'nmap)"
        category    = "Port Scan"
        severity    = "high"

    strings:
        $xmas = { 08 00 45 [8] 06 [23] 29 }   // FIN + PSH + URG
        $null = { 08 00 45 [8] 06 [23] 00 }   // aucun flag
        $fin  = { 08 00 45 [8] 06 [23] 01 }   // FIN seul, sans ACK

    condition:
        Is_Pcap and
        (#xmas > 10 or #null > 10 or #fin > 10)
}


/* ------------------------------------------------------------------ */
/*  3. Injection SQL                                                   */
/*  Fonctionne sur une capture, mais aussi sur des logs HTTP ou des    */
/*  payloads bruts (pas de condition Is_Pcap).                         */
/* ------------------------------------------------------------------ */

rule SQL_Injection
{
    meta:
        description = "Motifs d'injection SQL en clair ou encodés URL"
        category    = "SQL Injection"
        severity    = "high"

    strings:
        // UNION [ALL] SELECT (espaces, +, %20 ou commentaires /**/)
        $union      = /union(\s|\+|%20|\/\*[^*]*\*\/)+(all(\s|\+|%20)+)?select/ nocase

        // ' OR 1=1  /  ' AND 'a'='a
        $tautology  = /('|%27)(\s|\+|%20)*(or|and)(\s|\+|%20)+('|%27)?\w+('|%27)?(\s|\+|%20)*(=|%3d)(\s|\+|%20)*('|%27)?\w+/ nocase

        // Fermeture de chaîne suivie d'un commentaire : ' --  ou  ' #
        $comment    = /('|%27)(\s|\+|%20)*(--|%2d%2d|#|%23)/ nocase

        // Injections temporelles (blind)
        $time_fn    = /(sleep|pg_sleep|benchmark)(\s|\+|%20)*(\(|%28)/ nocase
        $waitfor    = /waitfor(\s|\+|%20)+delay/ nocase

        // Reconnaissance du schéma
        $info_schema = "information_schema" nocase

        // Requêtes empilées destructrices
        $stacked    = /(;|%3b)(\s|\+|%20)*(drop|truncate)(\s|\+|%20)+table/ nocase

    condition:
        any of ($union, $time_fn, $waitfor, $stacked) or
        2 of them
}
