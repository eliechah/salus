rule AWS_Secret_Key
{
    strings:
        $aws_key = "AKIA1234ABCD5678EFGH"
    condition:
        $aws_key
}


rule Google_API_Key
{
    meta:
        description = "Detect Google API keys"
        severity = "high"
    strings:
        $google_key = /AIza[0-9A-Za-z\\-_]{35}/
    condition:
        $google_key
}

rule Slack_Token
{
    meta:
        description = "Detect Slack Tokens"
        severity = "high"
    strings:
        $slack_token = /xox[baprs]-([0-9a-zA-Z]{10,48})?/
    condition:
        $slack_token
}

rule Heroku_API_Key
{
    meta:
        description = "Detect Heroku API Keys"
        severity = "high"
    strings:
        $heroku_key = /[hH]eroku[a-zA-Z0-9]{32}/
    condition:
        $heroku_key
}

rule JWT_Token
{
    meta:
        description = "Detect JWT tokens"
        severity = "medium"
    strings:
        $jwt = /eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+/
    condition:
        $jwt
}

rule Suspicious_Functions
{
    meta:
        description = "Detect usage of potentially dangerous functions"
        severity = "medium"
    strings:
        $eval = "eval("
        $exec = "exec("
        $subprocess = "subprocess.call("
        $pickle = "pickle.load("
    condition:
        any of them
}
