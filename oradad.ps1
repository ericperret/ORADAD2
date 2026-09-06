#requires -Version 5.1
#
# Fichier    : oradad.ps1
# Modifie par: Eric
# Date       : 2026-09-06
# Version    : 2.0
# Objet      : reimplementation en PowerShell natif (System.DirectoryServices.Protocols,
#              inclus dans Windows, aucune librairie externe, aucune compilation) du moteur
#              d'extraction LDAP d'ORADAD. Pilote entierement par config-oradad.xml et
#              oradad-schema.xml (aucune donnee de schema recopiee en dur dans ce fichier,
#              hors les tables de flags ci-dessous qui n'existent nulle part ailleurs en XML).
#              Sortie strictement conforme a format-sortie-oradad.json (UTF-16LE+BOM, TAB,
#              CRLF, sans echappement).
#
# VERSION 2.0 : fusion d'oradad-complement.ps1 (v2.0) dans ce fichier. Les deux scripts
#              partageaient deux implementations independantes de la connexion LDAP
#              (Connect-OradadLdap / Connect-OradadLdapMinimal) - duplication corrigee en
#              les fusionnant : une seule connexion, un seul fichier. Desactivable avec
#              -SkipComplement (utile pour un run LDAP seul, plus rapide, sans acces SYSVOL).
#
# Perimetre COUVERT et verifie (voir CHANGELOG-oradad-ps1.md pour le detail des citations) :
#   - lecture config-oradad.xml (level, confidential, outputFiles) et oradad-schema.xml
#     (requests, rootDSEAttributes, attributes, classes)
#   - resolution classes -> attributs, filtrage niveau/confidentialite (logique LDAP.cpp)
#   - tous les types d'attributs : STR, STRS, INT, INT64, SID, SD, DACL, GUID, DATE,
#     DATEINT64, BOOL, BIN, avec filtres (userAccountControl, groupType, trustAttributes,
#     trustDirection, trustType, systemFlags, searchFlags, schemaFlagsEx,
#     supportedEncryptionTypes, sid, Filetime, NegFiletime)
#   - recherche LDAP paginee + attributs a plage (range) pour les multivalues > 1500
#   - en-tete de colonnes, fichier 'top' avec shortname/shortdn, tables.tsv, metadata.tsv
#   - (ex-complement) ACL/SD explicites SYSVOL, proprietes de zones DNS (dNSProperty
#     decode selon MS-DNSP 2.3.2.1.1), reliquat FRS (nTFRSSettings) - lecture seule
#
# Perimetre HORS de ce script :
#   - Contenu des fichiers SYSVOL/GPO (hors sujet : "extractions AD via LDAP" uniquement,
#     demande explicitement) - seules leurs ACL sont lues, pas leur contenu
#   - autoGetDomain/autoGetTrusts (enumeration multi-domaines de la foret) : ce script cible
#     UN SEUL serveur/domaine par execution (parametres -Server/-Domain). Pour une foret
#     entiere, relancer le script par domaine.
#   - Path1/Path2 (nommage de dossier de sortie par sous-base) : approxime au mieux
#     (cf. CHANGELOG), la logique exacte d'Engine.cpp n'a pas ete relue en entier.
#
# NON TESTE contre un AD reel (aucun AD disponible dans l'environnement de redaction).
# Les formateurs de types/filtres, la resolution de schema, et le decodage dNSProperty
# SONT testes unitairement (cf. test-*.ps1 du meme lot).
#

[CmdletBinding()]
param(
    [string]$ConfigPath = ".\config-oradad.xml",
    [string]$SchemaPath = ".\oradad-schema.xml",
    [string]$OutputDir  = ".\output",
    [string]$Server     = $null,      # vide = domaine courant (DC locator)
    [System.Management.Automation.PSCredential]$Credential = $null,
    [string]$DomainDnsName = $null,   # override pour le chemin SYSVOL (sinon deduit du rootDSE)
    [switch]$SkipComplement           # desactive SYSVOL ACL / DNS zones / FRS (LDAP seul, plus rapide)
)

Add-Type -AssemblyName System.DirectoryServices.Protocols
Add-Type -AssemblyName System.DirectoryServices.ActiveDirectory

# ============================================================================
# Constantes (Constants.h)
# ============================================================================
$script:FILTER_FLAG = 1
$script:FILTER_TYPE = 2
$script:NEVER_VALUE_1 = 9223372036854775807   # 0x7FFFFFFFFFFFFFFF (Filters.cpp:10)
# NEVER_VALUE_2 (Filters.cpp:11, 2^63) n'est jamais atteignable dans pFilterFiletime :
# le test "llValue <= 0" (Filters.cpp:294) intercepte deja toute valeur negative/MinValue
# avant lui. Code mort dans l'original ; non reimplemente ici (comportement identique).

function New-OradadFlagItem { param([long]$Value, [string]$Text) [pscustomobject]@{ Value = $Value; Text = $Text } }

# Tables de flags (Constants.h) - ordre EXACT conserve. Tableaux d'objets, jamais de
# hashtable/[ordered] indexee par entier : PowerShell fait alors un acces POSITIONNEL
# (dict[1] = 2e element) et non une recherche par cle - piege verifie experimentalement.
$script:OradadFilters = @{
    userAccountControl = @{ Mode = $script:FILTER_FLAG; Items = @(
        (New-OradadFlagItem 0x00000002 'DISABLE'),        (New-OradadFlagItem 0x00000010 'LOCKOUT'),
        (New-OradadFlagItem 0x00000020 'PASSWD_NOTREQD'), (New-OradadFlagItem 0x00000040 'PASSWD_CANT_CHANGE'),
        (New-OradadFlagItem 0x00000080 'TEXT_PASSWORD'),  (New-OradadFlagItem 0x00800000 'PASSWORD_EXPIRED'),
        (New-OradadFlagItem 0x00010000 'DONT_EXPIRE_PASSWD'), (New-OradadFlagItem 0x00400000 'DONT_REQUIRE_PREAUTH'),
        (New-OradadFlagItem 0x00040000 'SMARTCARD_REQUIRED'), (New-OradadFlagItem 0x00200000 'USE_DES_KEY_ONLY'),
        (New-OradadFlagItem 0x00100000 'NOT_DELEGATED'),  (New-OradadFlagItem 0x00080000 'TRUSTED_FOR_DELEGATION'),
        (New-OradadFlagItem 0x01000000 'T2A4F'),          (New-OradadFlagItem 0x00000100 'TEMP_DUPLICATE_ACCOUNT'),
        (New-OradadFlagItem 0x00000200 'NORMAL_ACCOUNT'), (New-OradadFlagItem 0x00000800 'INTERDOMAIN_ACCOUNT'),
        (New-OradadFlagItem 0x00001000 'WORKSTATION_ACCOUNT'), (New-OradadFlagItem 0x00002000 'SERVER_ACCOUNT'),
        (New-OradadFlagItem 0x04000000 'PARTIAL_SECRETS_ACCOUNT'), (New-OradadFlagItem 0x00020000 'MNS_LOGON_ACCOUNT'),
        (New-OradadFlagItem 0x02000000 'NO_AUTH_DATA_REQUIRED'), (New-OradadFlagItem 0x00000001 'SCRIPT'),
        (New-OradadFlagItem 0x00000008 'HOMEDIR_REQUIRED')
    )}
    systemFlags = @{ Mode = $script:FILTER_FLAG; Items = @(
        (New-OradadFlagItem 0x00000001 'NOT_REPLICATED/NC'), (New-OradadFlagItem 0x00000002 'PARTIAL_SET_MEMBER/DOMAIN'),
        (New-OradadFlagItem 0x00000004 'CONSTRUCTED/NOT_GC_REPLICATED'), (New-OradadFlagItem 0x00000008 'OPERATIONAL'),
        (New-OradadFlagItem 0x00000010 'BASE_OBJECT'), (New-OradadFlagItem 0x00000020 'RDN'),
        (New-OradadFlagItem 0x02000000 'DISALLOW_MOVE_ON_DELETE'), (New-OradadFlagItem 0x04000000 'DISALLOW_MOVE'),
        (New-OradadFlagItem 0x08000000 'DISALLOW_RENAME'), (New-OradadFlagItem 0x10000000 'ALLOW_LIMITED_MOVE'),
        (New-OradadFlagItem 0x20000000 'ALLOW_MOVE'), (New-OradadFlagItem 0x40000000 'ALLOW_RENAME'),
        (New-OradadFlagItem 0x80000000 'DISALLOW_DELETE')
    )}
    searchFlags = @{ Mode = $script:FILTER_FLAG; Items = @(
        (New-OradadFlagItem 0x0001 'ATTINDEX'), (New-OradadFlagItem 0x0002 'PDNTATTINDEX'),
        (New-OradadFlagItem 0x0004 'ANR'), (New-OradadFlagItem 0x0008 'PRESERVEONDELETE'),
        (New-OradadFlagItem 0x0010 'COPY'), (New-OradadFlagItem 0x0020 'TUPLEINDEX'),
        (New-OradadFlagItem 0x0040 'SUBTREEATTINDEX'), (New-OradadFlagItem 0x0080 'CONFIDENTIAL'),
        (New-OradadFlagItem 0x0100 'NEVERVALUEAUDIT'), (New-OradadFlagItem 0x0200 'RODCFilteredAttribute'),
        (New-OradadFlagItem 0x0400 'EXTENDEDLINKTRACKING'), (New-OradadFlagItem 0x0800 'BASEONLY'),
        (New-OradadFlagItem 0x1000 'PARTITIONSECRET')
    )}
    schemaFlagsEx = @{ Mode = $script:FILTER_FLAG; Items = @( (New-OradadFlagItem 0x1 'IS_CRITICAL') ) }
    groupType = @{ Mode = $script:FILTER_FLAG; Items = @(
        (New-OradadFlagItem 0x1 'BUILTIN_LOCAL'), (New-OradadFlagItem 0x2 'ACCOUNT'),
        (New-OradadFlagItem 0x4 'RESOURCE'), (New-OradadFlagItem 0x8 'UNIVERSAL'),
        (New-OradadFlagItem 0x10 'APP_BASIC'), (New-OradadFlagItem 0x20 'APP_QUERY'),
        (New-OradadFlagItem 0x80000000 'SECURITY_ENABLED')
    )}
    supportedEncryptionTypes = @{ Mode = $script:FILTER_FLAG; Items = @(
        (New-OradadFlagItem 0x1 'DES_CRC'), (New-OradadFlagItem 0x2 'DES_MD5'),
        (New-OradadFlagItem 0x4 'RC4'), (New-OradadFlagItem 0x8 'AES128'),
        (New-OradadFlagItem 0x10 'AES256'), (New-OradadFlagItem 0x20000 'Compound'),
        (New-OradadFlagItem 0x10000 'FAST'), (New-OradadFlagItem 0x40000 'Claims'),
        (New-OradadFlagItem 0x80000 'SID_compression_disabled')
    )}
    trustAttributes = @{ Mode = $script:FILTER_FLAG; Items = @(
        (New-OradadFlagItem 0x1 'NON_TRANSITIVE'), (New-OradadFlagItem 0x2 'UPLEVEL_ONLY'),
        (New-OradadFlagItem 0x4 'QUARANTINED_DOMAIN'), (New-OradadFlagItem 0x8 'FOREST_TRANSITIVE'),
        (New-OradadFlagItem 0x10 'CROSS_ORGANIZATION'), (New-OradadFlagItem 0x20 'WITHIN_FOREST'),
        (New-OradadFlagItem 0x40 'TREAT_AS_EXTERNAL'), (New-OradadFlagItem 0x80 'USES_RC4_ENCRYPTION'),
        (New-OradadFlagItem 0x200 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'), (New-OradadFlagItem 0x400 'PIM_TRUST'),
        (New-OradadFlagItem 0x400000 'O_TREE_PARENT'), (New-OradadFlagItem 0x800000 'O_TREE_ROOT')
    )}
    trustDirection = @{ Mode = $script:FILTER_TYPE; Items = @(
        (New-OradadFlagItem 0x1 'INBOUND'), (New-OradadFlagItem 0x2 'OUTBOUND'), (New-OradadFlagItem 0x3 'BIDIRECTIONAL')
    )}
    trustType = @{ Mode = $script:FILTER_TYPE; Items = @(
        (New-OradadFlagItem 0x1 'DOWNLEVEL'), (New-OradadFlagItem 0x2 'UPLEVEL'), (New-OradadFlagItem 0x3 'MIT')
    )}
}

function Get-OradadFlagsText {
    param([string]$FilterName, [long]$Value)
    $def = $script:OradadFilters[$FilterName]
    if (-not $def) { return $null }
    if ($def.Mode -eq $script:FILTER_FLAG) {
        $parts = New-Object System.Collections.Generic.List[string]
        $rest = [uint32]$Value
        foreach ($item in $def.Items) {
            $iv = [uint32]$item.Value
            if (($iv -band $rest) -eq $iv) {
                $parts.Add($item.Text)
                $rest = $rest -band (-bnot $iv)
            }
        }
        if ($rest -ne 0) { $parts.Add([string]$rest) }
        return ($parts -join ' | ')
    }
    else {
        foreach ($item in $def.Items) {
            if ([uint32]$item.Value -eq [uint32]$Value) { return $item.Text }
        }
        return ''
    }
}

function Get-OradadFiletimeDuration {
    param([long]$Value)
    if ($Value -le 0) { return $null }
    if ($Value -eq $script:NEVER_VALUE_1) { return 'Never' }
    $v = [long]($Value / 10000000)
    $day = [long]($v / 86400); $v -= $day * 86400
    $hour = [long]($v / 3600); $v -= $hour * 3600
    $min  = [long]($v / 60);   $v -= $min * 60
    $sec  = [long]($v / 60)
    return ('{0}:{1:D2}:{2:D2}:{3:D2}' -f $day, $hour, $min, $sec)
}
function Get-OradadNegFiletimeDuration { param([long]$Value) Get-OradadFiletimeDuration(-$Value) }

function Get-OradadSidFilter {
    param([byte[]]$Bytes)
    try { return (New-Object System.Security.Principal.SecurityIdentifier($Bytes, 0)).Value }
    catch { return 'Unable to convert SID' }
}

function Invoke-OradadAttributeFilter {
    param([string]$FilterName, [object]$RawValue, [string]$RawType)
    switch ($FilterName) {
        'sid'         { return Get-OradadSidFilter -Bytes $RawValue }
        'Filetime'    { return Get-OradadFiletimeDuration -Value ([long]$RawValue) }
        'NegFiletime' { return Get-OradadNegFiletimeDuration -Value ([long]$RawValue) }
        default       { return Get-OradadFlagsText -FilterName $FilterName -Value ([long]$RawValue) }
    }
}

# ============================================================================
# Chargement config-oradad.xml / oradad-schema.xml, resolution classes->attributs
# ============================================================================
function Import-OradadSchema {
    param([string]$ConfigPath, [string]$SchemaPath)

    [xml]$configXml = Get-Content -Path $ConfigPath -Encoding UTF8
    [xml]$schemaXml = Get-Content -Path $SchemaPath -Encoding UTF8

    $attrDefs = @{}
    foreach ($a in $schemaXml.schema.attributes.attribute) {
        $lim = 0
        if ($a.limit) { $lim = [int]$a.limit }
        $attrDefs[$a.name] = [pscustomobject]@{
            Name = $a.name; Level = [int]$a.level; Type = $a.type
            Confidential = ($a.flags -eq 'confidential'); Limit = $lim; Filter = $a.filter
        }
    }

    $rootDseAttrs = New-Object System.Collections.Generic.List[object]
    foreach ($a in $schemaXml.schema.rootDSEAttributes.attribute) {
        $lim = 0
        if ($a.limit) { $lim = [int]$a.limit }
        $rootDseAttrs.Add([pscustomobject]@{
            Name = $a.name; Level = [int]$a.level; Type = $a.type
            Confidential = ($a.flags -eq 'confidential'); Limit = $lim; Filter = $a.filter
        })
    }

    $classDefs = @{}
    foreach ($c in $schemaXml.schema.classes.class) {
        $classDefs[$c.name] = @($c.attribute | ForEach-Object { $_.name })
    }

    $requests = New-Object System.Collections.Generic.List[object]
    foreach ($r in $schemaXml.schema.requests.request) {
        $controls = New-Object System.Collections.Generic.List[object]
        if ($r.controls -and $r.controls.control) {
            foreach ($c in $r.controls.control) {
                $controls.Add([pscustomobject]@{ Oid = $c.oid; Critical = ($c.critical -eq 'true'); ValueType = $c.valueType; Value = $c.value })
            }
        }
        $requests.Add([pscustomobject]@{
            Name = $r.name; Description = $r.description; Base = $r.base; Scope = $r.scope
            Filter = $r.filter; Classes = $r.classes; Controls = $controls
        })
    }

    [pscustomobject]@{
        Level = [int]$configXml.config.level
        Confidential = [int]$configXml.config.confidential
        AttrDefs = $attrDefs
        RootDseAttrs = $rootDseAttrs
        ClassDefs = $classDefs
        Requests = $requests
    }
}

function Resolve-OradadRequestAttributes {
    param($Schema, [string]$ClassesText)
    $names = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($className in ($ClassesText -split ',')) {
        $className = $className.Trim()
        if ($Schema.ClassDefs.ContainsKey($className)) {
            foreach ($attrName in $Schema.ClassDefs[$className]) {
                if (-not $seen.ContainsKey($attrName)) {
                    $seen[$attrName] = $true
                    $names.Add($attrName) | Out-Null
                }
            }
        }
        else {
            Write-Warning "Classe absente de oradad-schema.xml <classes> : '$className'"
        }
    }
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($n in $names) {
        if ($Schema.AttrDefs.ContainsKey($n)) { $result.Add($Schema.AttrDefs[$n]) }
        else { Write-Warning "Attribut '$n' absent de oradad-schema.xml <attributes>" }
    }
    return $result
}

function Get-OradadFilteredAttributes {
    param([array]$Attrs, [int]$Level, [int]$Confidential)
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($attr in $Attrs) {
        if ($attr.Level -le $Level) {
            if (($Confidential -gt 0) -or (-not $attr.Confidential)) {
                $limit = if ($Confidential -ge 2) { 0 } else { $attr.Limit }
                $result.Add([pscustomobject]@{ Attr = $attr; Limit = $limit })
            }
            elseif ($attr.Limit -gt 0) {
                $result.Add([pscustomobject]@{ Attr = $attr; Limit = $attr.Limit })
            }
        }
    }
    return $result
}

# ============================================================================
# Formatage des valeurs par type (LDAP.cpp:750-1174)
# ============================================================================
function Format-OradadDateFromGeneralizedTime {
    # TYPE_DATE : reformatage des 14 premiers caracteres du GeneralizedTime LDAP brut.
    # Ce n'est PAS une conversion de date (pas de gestion fuseau/fraction), LDAP.cpp:1051-1083.
    param([string]$Raw)
    if ([string]::IsNullOrEmpty($Raw) -or $Raw.Length -lt 14) { return $Raw }
    $s = $Raw.Substring(0, 14)
    return "{0}-{1}-{2} {3}:{4}:{5}" -f $s.Substring(0,4), $s.Substring(4,2), $s.Substring(6,2), $s.Substring(8,2), $s.Substring(10,2), $s.Substring(12,2)
}

function Format-OradadDateInt64 {
    # TYPE_DATEINT64 : FILETIME -> SYSTEMTIME (LDAP.cpp:1085-1115 ; ORADAD.h:23-24)
    param([long]$Value)
    if ($Value -eq 0x7FFFFFFFFFFFFFFF) { return '2999-12-12 23:59:59' }
    if ($Value -eq 0) { return '' }
    return ([DateTime]::FromFileTimeUtc($Value)).ToString('yyyy-MM-dd HH:mm:ss')
}

function ConvertTo-OradadHex { param([byte[]]$Bytes) -join ($Bytes | ForEach-Object { $_.ToString('x2') }) }

function Format-OradadSingleValue {
    # Formate UNE valeur brute selon son Type ORADAD. Ne gere pas la jointure multivaleurs
    # (';') ni la limite de troncature : voir Format-OradadAttributeField.
    param([string]$Type, [object]$Raw, [string]$FilterName)

    switch ($Type) {
        'STR'  { return [string]$Raw }
        'STRS' { return [string]$Raw }
        'INT'  { return [string]$Raw }
        'INT64'{ return [string]$Raw }
        'BOOL' { if ([string]$Raw -eq 'TRUE') { return '1' } else { return '0' } }
        'GUID' { return ([Guid]::new([byte[]]$Raw)).ToString() }
        'DATE' { return Format-OradadDateFromGeneralizedTime -Raw ([string]$Raw) }
        'DATEINT64' { return Format-OradadDateInt64 -Value ([long][string]$Raw) }
        'SID'  { return Get-OradadSidFilter -Bytes ([byte[]]$Raw) }
        'SD'   { return ConvertTo-OradadHex -Bytes ([byte[]]$Raw) }
        'DACL' {
            try {
                $rsd = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$Raw, 0)
                return $rsd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
            } catch { return '' }
        }
        'BIN'  {
            if ($FilterName) {
                $f = Invoke-OradadAttributeFilter -FilterName $FilterName -RawValue $Raw -RawType $Type
                if ($null -ne $f) { return $f }
            }
            return ConvertTo-OradadHex -Bytes ([byte[]]$Raw)
        }
        default { return [string]$Raw }
    }
}

# ============================================================================
# Ecriture TSV (Buffer.cpp) : UTF-16LE + BOM, TAB, CRLF, pas d'echappement
# (les caracteres TAB/CR/LF a l'interieur d'une valeur sont remplaces par un
# espace avant ecriture - Util.cpp:128-147)
# ============================================================================
function Remove-OradadSpecialChars {
    param([string]$s)
    if ($null -eq $s) { return $s }
    return ($s -replace "[`t`r`n]", ' ')
}

function New-OradadTsvWriter {
    param([string]$Path)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $enc = New-Object System.Text.UnicodeEncoding($false, $true)   # UTF-16LE, BOM=true
    $writer = New-Object System.IO.StreamWriter($stream, $enc)
    $writer.AutoFlush = $false
    return $writer
}

function Write-OradadRow {
    param([System.IO.StreamWriter]$Writer, [string[]]$Fields)
    $clean = $Fields | ForEach-Object { Remove-OradadSpecialChars $_ }
    $Writer.Write(($clean -join "`t"))
    $Writer.Write("`r`n")
}

# ============================================================================
# Connexion LDAP (System.DirectoryServices.Protocols - .NET, aucune librairie
# tierce, fait partie de Windows/.NET depuis .NET Framework 2.0)
# ============================================================================
function Connect-OradadLdap {
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $id = if ($Server) { New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server) }
          else { New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($null) }
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
    $conn.SessionOptions.ProtocolVersion = 3
    if ($Credential) {
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        $nc = $Credential.GetNetworkCredential()
        $conn.Credential = New-Object System.Net.NetworkCredential($nc.UserName, $nc.Password, $nc.Domain)
    } else {
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    }
    $conn.Bind()
    return $conn
}

function Get-OradadRootDse {
    param([System.DirectoryServices.Protocols.LdapConnection]$Connection)
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest($null, '(objectClass=*)', 'Base', @(
        'defaultNamingContext','configurationNamingContext','schemaNamingContext','rootDomainNamingContext'
    ))
    $resp = $Connection.SendRequest($req)
    $entry = $resp.Entries[0]
    [pscustomobject]@{
        DefaultNamingContext     = [string]$entry.Attributes['defaultNamingContext'][0]
        ConfigurationNamingContext = [string]$entry.Attributes['configurationNamingContext'][0]
        SchemaNamingContext      = [string]$entry.Attributes['schemaNamingContext'][0]
        RootDomainNamingContext  = [string]$entry.Attributes['rootDomainNamingContext'][0]
    }
}

function Resolve-OradadBaseKeyword {
    # Traduit un mot-cle de <base> (rootDSE/domain/configuration/schema/domainDNS/forestDNS)
    # en DN LDAP reel, a partir du rootDSE. cf. oradad-schema.xml (vocabulaire verifie
    # exhaustivement : rootDSE, domain, configuration, schema, domainDNS, forestDNS).
    param([string]$Keyword, $RootDse)
    switch ($Keyword) {
        'rootDSE'       { return $null }
        'domain'        { return $RootDse.DefaultNamingContext }
        'configuration' { return $RootDse.ConfigurationNamingContext }
        'schema'        { return $RootDse.SchemaNamingContext }
        'domainDNS'     { return "DC=DomainDnsZones,$($RootDse.DefaultNamingContext)" }
        'forestDNS'     { return "DC=ForestDnsZones,$($RootDse.RootDomainNamingContext)" }
        default         { Write-Warning "Mot-cle <base> inconnu : '$Keyword'"; return $null }
    }
}

function New-OradadControl {
    param($ControlDef)
    switch ($ControlDef.Oid) {
        '1.2.840.113556.1.4.801' {
            # LDAP_SERVER_SD_FLAGS_OID : classe .NET dediee (encodage BER de l'entier geré nativement)
            $flags = [Convert]::ToInt32($ControlDef.Value, 16)
            return New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($flags)
        }
        default {
            return New-Object System.DirectoryServices.Protocols.DirectoryControl($ControlDef.Oid, $null, $ControlDef.Critical, $true)
        }
    }
}

function Get-OradadRangedValues {
    # Poursuit la recuperation d'un attribut multivalue renvoye avec suffixe
    # ';range=X-Y' (limite serveur AD, LDAP.cpp pParseRange/pGetRangedAttribute).
    param([System.DirectoryServices.Protocols.LdapConnection]$Connection, [string]$Dn, [string]$AttrName)
    $values = New-Object System.Collections.Generic.List[object]
    $rangeEnd = 0
    while ($true) {
        $rangeAttr = "$AttrName;range=$($rangeEnd+1)-*"
        if ($rangeEnd -eq 0) { $rangeAttr = "$AttrName;range=0-*" }
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest($Dn, '(objectClass=*)', 'Base', @($rangeAttr))
        $resp = $Connection.SendRequest($req)
        if ($resp.Entries.Count -eq 0) { break }
        $entry = $resp.Entries[0]
        $matched = $entry.Attributes.AttributeNames | Where-Object { $_ -like "$AttrName;range=*" }
        if (-not $matched) { break }
        $attr = $entry.Attributes[$matched[0]]
        foreach ($v in $attr.GetValues([string])) { $values.Add($v) }
        if ($matched[0] -like '*-*') {
            $upper = ($matched[0] -split '-')[1]
            if ($upper -eq '*') { break }
            $rangeEnd = [int]$upper
        } else { break }
    }
    return $values
}

# ============================================================================
# Ecriture d'une requete (equivalent LdapProcessRequest, LDAP.cpp:219+)
# ============================================================================
function Invoke-OradadRequest {
    param($Connection, $Schema, $Request, [string]$OutputDir, $RootDse, [string]$DomainLabel)

    $isRootDse = ($Request.Base -eq 'rootDSE')
    $isTop = ($Request.Name -eq 'top')

    if ($isRootDse) {
        $rawAttrs = $Schema.RootDseAttrs
    } else {
        $rawAttrs = Resolve-OradadRequestAttributes -Schema $Schema -ClassesText $Request.Classes
    }
    $filtered = Get-OradadFilteredAttributes -Attrs $rawAttrs -Level $Schema.Level -Confidential $Schema.Confidential
    if ($filtered.Count -eq 0 -and -not $isRootDse) {
        Write-Verbose "Requete '$($Request.Name)' : aucun attribut apres filtrage, ignoree."
        return
    }

    $keywords = @($Request.Base -split ',' | ForEach-Object { $_.Trim() })
    $multiBase = $keywords.Count -gt 1

    # Nommage : <domaine>\<sousBase>\<requete>.tsv (multi-bases) ou <domaine>\<requete>.tsv
    if ($multiBase) {
        $dir = Join-Path $OutputDir $DomainLabel
    } else {
        $dir = Join-Path $OutputDir $DomainLabel
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    foreach ($keyword in $keywords) {
        $baseDn = Resolve-OradadBaseKeyword -Keyword $keyword -RootDse $RootDse
        if (-not $isRootDse -and -not $baseDn) { continue }

        $fileDir = if ($multiBase) { Join-Path $dir $keyword } else { $dir }
        New-Item -ItemType Directory -Path $fileDir -Force | Out-Null
        $filePath = Join-Path $fileDir "$($Request.Name).tsv"

        $writer = New-OradadTsvWriter -Path $filePath
        try {
            # --- En-tete ---
            $header = New-Object System.Collections.Generic.List[string]
            $header.Add($(if ($isRootDse) { 'server' } else { 'dn' }))
            if ($isTop) { $header.Add('shortname'); $header.Add('shortdn') }
            foreach ($fa in $filtered) {
                $header.Add($fa.Attr.Name)
                if (($fa.Attr.Type -eq 'INT' -or $fa.Attr.Type -eq 'INT64') -and $fa.Attr.Filter) {
                    $header.Add("$($fa.Attr.Name)_int")
                }
            }
            Write-OradadRow -Writer $writer -Fields $header

            # --- Controles ---
            $controls = @($Request.Controls | ForEach-Object { New-OradadControl $_ })

            # --- Recherche paginee ---
            $attrNames = @($filtered | ForEach-Object { $_.Attr.Name })
            $scope = switch ($Request.Scope) {
                'subtree' { [System.DirectoryServices.Protocols.SearchScope]::Subtree }
                'onelevel'{ [System.DirectoryServices.Protocols.SearchScope]::OneLevel }
                default   { [System.DirectoryServices.Protocols.SearchScope]::Base }
            }
            $filterStr = if ($Request.Filter) { $Request.Filter } else { '(objectClass=*)' }
            $pageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(1000)

            do {
                $req = New-Object System.DirectoryServices.Protocols.SearchRequest($baseDn, $filterStr, $scope, $attrNames)
                $req.Controls.Add($pageControl) | Out-Null
                foreach ($c in $controls) { $req.Controls.Add($c) | Out-Null }

                $resp = $Connection.SendRequest($req)

                foreach ($entry in $resp.Entries) {
                    $row = New-Object System.Collections.Generic.List[string]

                    if ($isRootDse) {
                        $row.Add($Connection.SessionOptions.HostName)
                    } else {
                        $row.Add($entry.DistinguishedName)
                    }

                    if ($isTop) {
                        $row.Add("$DomainLabel/$keyword")
                        $shortDn = $entry.DistinguishedName
                        if ($baseDn -and $shortDn -and $shortDn.ToLower().EndsWith(",$($baseDn.ToLower())")) {
                            $shortDn = $shortDn.Substring(0, $shortDn.Length - $baseDn.Length - 1)
                        } elseif ($shortDn -eq $baseDn) {
                            $shortDn = ''
                        }
                        $row.Add($shortDn)
                    }

                    foreach ($fa in $filtered) {
                        $attr = $fa.Attr
                        $ldapAttr = $entry.Attributes[$attr.Name]

                        if (-not $ldapAttr) {
                            $row.Add('')
                            if (($attr.Type -eq 'INT' -or $attr.Type -eq 'INT64') -and $attr.Filter) { $row.Add('') }
                            continue
                        }

                        $isBinaryType = @('SID','SD','DACL','GUID','BIN') -contains $attr.Type

                        if ($attr.Type -eq 'STRS') {
                            $raw = $ldapAttr.GetValues([string])
                            $joined = ($raw | ForEach-Object { Format-OradadSingleValue -Type 'STR' -Raw $_ -FilterName $null }) -join ';'
                            $row.Add($joined)
                        }
                        elseif (($attr.Type -eq 'INT' -or $attr.Type -eq 'INT64') -and $attr.Filter) {
                            $rawVal = $ldapAttr.GetValues([string])[0]
                            $filteredText = Invoke-OradadAttributeFilter -FilterName $attr.Filter -RawValue $rawVal -RawType $attr.Type
                            $row.Add([string]$filteredText)
                            $row.Add([string]$rawVal)
                        }
                        elseif ($attr.Type -eq 'BIN') {
                            $rawVals = $ldapAttr.GetValues([byte[]])
                            $joined = ($rawVals | ForEach-Object { Format-OradadSingleValue -Type 'BIN' -Raw $_ -FilterName $attr.Filter }) -join ';'
                            $row.Add($joined)
                        }
                        elseif ($attr.Type -eq 'SID') {
                            $rawVals = $ldapAttr.GetValues([byte[]])
                            $joined = ($rawVals | ForEach-Object { Get-OradadSidFilter -Bytes $_ }) -join ';'
                            $row.Add($joined)
                        }
                        elseif ($isBinaryType) {
                            $rawVal = $ldapAttr.GetValues([byte[]])[0]
                            $row.Add((Format-OradadSingleValue -Type $attr.Type -Raw $rawVal -FilterName $attr.Filter))
                        }
                        else {
                            $rawVal = $ldapAttr.GetValues([string])[0]
                            $row.Add((Format-OradadSingleValue -Type $attr.Type -Raw $rawVal -FilterName $attr.Filter))
                        }
                    }

                    Write-OradadRow -Writer $writer -Fields $row
                }

                $pageResp = $resp.Controls | Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }
                if ($pageResp) { $pageControl.Cookie = $pageResp.Cookie } else { break }
            } while ($pageControl.Cookie.Length -gt 0)
        }
        finally {
            $writer.Flush()
            $writer.Dispose()
        }

        Write-Host "  -> $filePath"
    }
}

# ============================================================================
# Complement (ex-oradad-complement.ps1, fusionne v2.0) : ce que le LDAP seul ne
# revele pas - ACL SYSVOL, proprietes de zones DNS, reliquat FRS. Reutilise la
# connexion LDAP et le rootDSE deja etablis par Start-Oradad (plus de connexion
# dupliquee). Lecture seule : uniquement Get-Acl/Get-ChildItem et des recherches
# LDAP, jamais de Set-*/Remove-*.
# ============================================================================
function Sanitize {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    return ($Value -replace "[`t`r`n]", " ")
}

function Write-OradadTsv {
    param([array]$Rows, [string]$Path)
    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Warning "Aucune ligne pour $Path - fichier non cree."
        return
    }
    $props = $Rows[0].PSObject.Properties.Name
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(($props -join "`t"))
    foreach ($row in $Rows) {
        $vals = $props | ForEach-Object { Sanitize $row.$_ }
        $lines.Add(($vals -join "`t"))
    }
    # CRLF force explicitement (WriteAllLines/Environment.NewLine n'est pas fiable hors Windows).
    $content = ($lines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($Path, $content, [System.Text.Encoding]::Unicode)
    Write-Host "Ecrit : $Path ($($Rows.Count) ligne(s))"
}

# --- 1. SYSVOL : ACL/SD explicites (Get-Acl : PowerShell natif, pas de RSAT) ---
function Get-SysvolAcl {
    param([string]$DomainDnsName)

    $rows = [System.Collections.Generic.List[object]]::new()

    if (-not $DomainDnsName) {
        try {
            $DomainDnsName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
        } catch {
            Write-Warning "Impossible de determiner le domaine (machine non jointe a un AD ?) - etape SYSVOL ignoree. Utiliser -DomainDnsName pour forcer."
            return $rows
        }
    }

    $sysvolPath = "\\$DomainDnsName\SYSVOL\$DomainDnsName"
    if (-not (Test-Path -LiteralPath $sysvolPath)) {
        Write-Warning "SYSVOL introuvable a $sysvolPath - verifier l'acces reseau - etape ignoree."
        return $rows
    }

    function Add-AclRow {
        param([string]$Path, [string]$Kind)
        try {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $explicit = $acl.Access | Where-Object { -not $_.IsInherited }
            # $rows capture par closure (List[object], type reference) : .Add() modifie
            # directement la liste de l'appelant. Ne jamais utiliser $script:rows ici -
            # $script: vise le scope du fichier, pas celui de Get-SysvolAcl (bug verifie
            # experimentalement : la fonction retournait alors toujours vide).
            $rows.Add([PSCustomObject]@{
                path             = $Path
                kind             = $Kind
                owner            = $acl.Owner
                sddl             = $acl.Sddl
                explicitAceCount = $explicit.Count
                explicitAces     = ($explicit | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights):$($_.AccessControlType)" }) -join ";"
            })
        } catch {
            Write-Warning "Get-Acl a echoue sur $Path : $($_.Exception.Message)"
        }
    }

    Add-AclRow -Path $sysvolPath -Kind "sysvol_root"
    $policiesPath = Join-Path $sysvolPath "Policies"
    if (Test-Path -LiteralPath $policiesPath) {
        Add-AclRow -Path $policiesPath -Kind "policies_root"
        Get-ChildItem -LiteralPath $policiesPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $gpoFolder = $_.FullName
            Add-AclRow -Path $gpoFolder -Kind "gpo_folder"
            foreach ($rel in @(
                "Machine\Registry.pol",
                "User\Registry.pol",
                "Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            )) {
                $f = Join-Path $gpoFolder $rel
                if (Test-Path -LiteralPath $f) { Add-AclRow -Path $f -Kind "gpo_file" }
            }
        }
    }
    return $rows
}

# --- 2. Zones DNS : dNSProperty en LDAP direct, decodage binaire MS-DNSP 2.3.2.1.1 ---
$script:DSPROPERTY_ZONE_ALLOW_UPDATE = 0x00000002   # fAllowUpdate : 0=OFF,1=UNSECURE,2=SECURE
$script:DSPROPERTY_ZONE_AGING_STATE  = 0x00000040   # fAging : booleen (32 bits)

function ConvertFrom-OradadDnsProperty {
    # dnsProperty (MS-DNSP 2.3.2.1.1) : DataLength(4) NameLength(4,ignore) Flag(4)
    # Version(4) Id(4) Data(DataLength) Name(1,ignore). Verifie sur blob synthetique conforme
    # a la doc protocolaire Microsoft (learn.microsoft.com/openspecs/windows_protocols/ms-dnsp).
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 20) { return $null }
    $dataLength = [BitConverter]::ToUInt32($Bytes, 0)
    $id = [BitConverter]::ToUInt32($Bytes, 16)
    $data = $null
    if ($dataLength -ge 4 -and $Bytes.Length -ge 24) { $data = [BitConverter]::ToUInt32($Bytes, 20) }
    [pscustomobject]@{ Id = $id; DataLength = $dataLength; Data = $data }
}

function Get-DnsZoneProperties {
    param($Connection, [string]$DefaultNamingContext)

    $rows = [System.Collections.Generic.List[object]]::new()
    $searchBases = @(
        "DC=DomainDnsZones,$DefaultNamingContext"
        "CN=MicrosoftDNS,CN=System,$DefaultNamingContext"
    )

    foreach ($base in $searchBases) {
        $resp = $null
        try {
            $req = New-Object System.DirectoryServices.Protocols.SearchRequest($base, '(objectClass=dnsZone)', 'OneLevel', @('name','dNSProperty'))
            $resp = $Connection.SendRequest($req)
        } catch {
            Write-Verbose "Base '$base' inaccessible ou absente : $($_.Exception.Message)"
            continue
        }

        foreach ($entry in $resp.Entries) {
            $zoneName = if ($entry.Attributes['name']) { [string]$entry.Attributes['name'][0] } else { $entry.DistinguishedName }
            $allowUpdate = $null; $agingState = $null

            if ($entry.Attributes['dNSProperty']) {
                foreach ($val in $entry.Attributes['dNSProperty'].GetValues([byte[]])) {
                    $prop = ConvertFrom-OradadDnsProperty -Bytes $val
                    if (-not $prop) { continue }
                    if ($prop.Id -eq $script:DSPROPERTY_ZONE_ALLOW_UPDATE) { $allowUpdate = $prop.Data }
                    elseif ($prop.Id -eq $script:DSPROPERTY_ZONE_AGING_STATE) { $agingState = $prop.Data }
                }
            }

            $updateText = switch ($allowUpdate) {
                0 { 'OFF' }; 1 { 'UNSECURE' }; 2 { 'SECURE' }; default { '' }
            }
            $agingText = if ($null -eq $agingState) { '' } elseif ($agingState -ne 0) { 'TRUE' } else { 'FALSE' }

            $rows.Add([PSCustomObject]@{
                zone              = $zoneName
                base              = $base
                dynamicUpdate     = $updateText
                dynamicUpdateRaw  = $allowUpdate
                agingEnabled      = $agingText
            })
        }
    }
    return $rows
}

# --- 3. Reliquat FRS : LDAP brut ---
function Get-FrsRemnant {
    param($Connection, [string]$DefaultNamingContext)
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest($DefaultNamingContext, '(objectClass=nTFRSSettings)', 'Subtree', @('distinguishedName'))
        $resp = $Connection.SendRequest($req)
        foreach ($entry in $resp.Entries) {
            $rows.Add([PSCustomObject]@{ dn = $entry.DistinguishedName; objectClass = 'nTFRSSettings' })
        }
    } catch {
        Write-Warning "Recherche LDAP nTFRSSettings en echec : $($_.Exception.Message)"
    }
    return $rows
}

function Invoke-OradadComplement {
    param($Connection, $RootDse, [string]$OutputDir, [string]$DomainDnsName)

    Write-Host "=== Complement : SYSVOL (ACL/SD) ==="
    Write-OradadTsv (Get-SysvolAcl -DomainDnsName $DomainDnsName) (Join-Path $OutputDir "sysvol_acl.tsv")

    Write-Host "`n=== Complement : zones DNS (dNSProperty) ==="
    Write-OradadTsv (Get-DnsZoneProperties -Connection $Connection -DefaultNamingContext $RootDse.DefaultNamingContext) (Join-Path $OutputDir "dns_zones.tsv")

    Write-Host "`n=== Complement : reliquat FRS ==="
    Write-OradadTsv (Get-FrsRemnant -Connection $Connection -DefaultNamingContext $RootDse.DefaultNamingContext) (Join-Path $OutputDir "frs_remnant.tsv")
}

# ============================================================================
# Main
# ============================================================================
function Start-Oradad {
    param([string]$ConfigPath, [string]$SchemaPath, [string]$OutputDir, [string]$Server, $Credential, [string]$DomainDnsName, [switch]$SkipComplement)

    Write-Host "Chargement config/schema..."
    $schema = Import-OradadSchema -ConfigPath $ConfigPath -SchemaPath $SchemaPath

    Write-Host "Connexion LDAP..."
    $conn = Connect-OradadLdap -Server $Server -Credential $Credential
    $rootDse = Get-OradadRootDse -Connection $conn
    $domainLabel = ($rootDse.DefaultNamingContext -replace '^DC=', '' -replace ',DC=', '.')

    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    foreach ($request in $schema.Requests) {
        Write-Host "Requete '$($request.Name)'..."
        try {
            Invoke-OradadRequest -Connection $conn -Schema $schema -Request $request -OutputDir $OutputDir -RootDse $rootDse -DomainLabel $domainLabel
        } catch {
            Write-Warning "Requete '$($request.Name)' en erreur : $($_.Exception.Message)"
        }
    }

    if (-not $SkipComplement) {
        $effectiveDomainDnsName = if ($DomainDnsName) { $DomainDnsName } else { $domainLabel }
        try {
            Invoke-OradadComplement -Connection $conn -RootDse $rootDse -OutputDir $OutputDir -DomainDnsName $effectiveDomainDnsName
        } catch {
            Write-Warning "Complement (SYSVOL/DNS/FRS) en erreur : $($_.Exception.Message)"
        }
    }

    Write-Host "Termine. Sortie : $OutputDir"
}

Start-Oradad -ConfigPath $ConfigPath -SchemaPath $SchemaPath -OutputDir $OutputDir -Server $Server -Credential $Credential -DomainDnsName $DomainDnsName -SkipComplement:$SkipComplement
