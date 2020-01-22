#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.0.2.0'}, @{ModuleName='AWS.Tools.S3';ModuleVersion='4.0.2.0'}, @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.0.2.0'}
$objects = Get-S3Object -BucketName "awslambdapowershelldemo"
foreach($object in $objects)
{
    $firstSlash = $object.Key.IndexOf("/")
    $secondSlash = $object.Key.IndexOf("/",$firstSlash+1)-$firstSlash-1
    $entity = $object.Key.Substring(0,$firstSlash)
    $roleName = $object.Key.Substring($firstSlash+1,$secondSlash)
    $policyName = $object.Key.Substring($firstSlash+$secondSlash+2,$object.Key.IndexOf(".")-$firstSlash-$secondSlash-2)
    if($entity -match "^[0-9]{12}$")
    {
        $policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "$entity"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
"@
        $role = New-IAMRole -RoleName "$roleName" -AssumeRolePolicyDocument $policy
    }
    else
    {
        $policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "$entity.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
"@
        $role = New-IAMRole -RoleName "$roleName" -AssumeRolePolicyDocument $policy
    }
    if($policyName -eq "managed")
    {
        $file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName "awslambdapowershelldemo" -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "$entity/$roleName/$policyName.json")
        $json = [System.Text.Encoding]::ASCII.GetString($file.content)
        $jsonObject = ConvertFrom-Json $json
        foreach($arn in $jsonObject.arn)
        {
            Register-IAMRolePolicy -RoleName "$roleName" -PolicyArn "$arn"
        }
    }
    else
    {
        $file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName "awslambdapowershelldemo" -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "$entity/$roleName/$policyName.json")
        $json = [System.Text.Encoding]::ASCII.GetString($file.content)
        Write-IAMRolePolicy -RoleName "$roleName" -PolicyDocument $json -PolicyName "$policyName"
    }
}
