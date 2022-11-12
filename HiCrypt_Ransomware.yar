rule HiCrypt_Ransomware {
    meta:
        author         = "Chase Sims"
        description    = "This signature detects the HiCrypt Ransomware variant."
        created_date   = "2022-11-04"
        updated_date   = "2022-11-12"
        samples        = "fb1068b3e09e913bb8434cdf99b119e333be3c638787a3c6973cae0507700535"
    strings:
        $sig= "FromSiberiaWithLove" ascii wide nocase
        $str1= "wevtutil.exe cl application" ascii wide nocase
        $str2= "wevtutil.exe cl system" ascii wide nocase
        $str3= "wevtutil.exe cl security" ascii wide nocase
        $str4= "Everything.exe" ascii wide nocase
        $cmd1= /ping \d+[.]\d \-n 5 \& fsutil file setZeroData offset\=\d length\=\d+/ ascii wide
        $func1= {0f 10 05 d8 9e 5d 00}
        $func2= {68 68 a2 5d 00}
        $func3= {68 14 a4 5d 00}
    condition:
        (uint16(0) == 0x5a4d and $cmd1 and $sig and 3 of ($func*) and 2 of ($str*))
}