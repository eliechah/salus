rule AWS_Secret_Key
{
    meta:
        description = "Detects AWS Secret Access Keys"
        severity = "high"
    strings:
        $aws_key = /AKIA[0-9A-Z]{16}/
    condition:
        $aws_key
}
