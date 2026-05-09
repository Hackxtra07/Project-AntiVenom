rule Generic_Suspicious_Strings {
    strings:
        $s1 = "eval(base64_decode"
        $s2 = "system("
        $s3 = "exec("
    condition:
        any of them
}
