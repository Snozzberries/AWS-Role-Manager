$bucket = New-S3Bucket -BucketName "awslambdapowershelldemo1"
Add-S3PublicAccessBlock -BucketName $bucket.BucketName -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -PublicAccessBlockConfiguration_IgnorePublicAcl $true -PublicAccessBlockConfiguration_RestrictPublicBucket $true

$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
"@
$role = New-IAMRole -RoleName "ROLE-RoleManager" -AssumeRolePolicyDocument $policy

$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }
    ]
}
"@
Write-IAMRolePolicy -RoleName "ROLE-RoleManager" -PolicyDocument $policy -PolicyName "POLICY-ROLE-RoleManager"
Register-IAMRolePolicy -RoleName "ROLE-RoleManager" -PolicyArn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "$($role.Arn)"
                ]
            },
            "Action": [
                "s3:*"
            ],
            "Resource": [
                "arn:aws:s3:::$($bucket.BucketName)",
                "arn:aws:s3:::$($bucket.BucketName)/*"
            ]
        }
    ]
}
"@
Write-S3BucketPolicy -BucketName $($bucket.BucketName) -Policy $policy

New-AWSPowerShellLambda -ScriptName FUNCTION-RoleManager-1 -Template Basic

Publish-AWSPowerShellLambda -ScriptPath .\FUNCTION-RoleManager-1.ps1 -Name FUNCTION-RoleManager-1 -IAMRoleArn $role.Arn

$lambda = Get-LMFunctionList|Where-Object{$_.Role -eq $role.Arn}
$rule = Write-CWERule -Name "RULE-CronHourly" -ScheduleExpression "rate(1 hour)" -State ENABLED
$target = New-Object Amazon.CloudWatchEvents.Model.Target
$target.Arn = $lambda.FunctionArn
$target.Id = $lambda.RevisionId
Write-CWETarget -Rule $rule.Substring($rule.IndexOf("/")+1) -Target $target
Add-LMPermission -FunctionName $lambda.FunctionName -Action "lambda:InvokeFunction" -Principal "events.amazonaws.com" -StatementId $rule.Substring($rule.IndexOf("/")+1) -SourceArn $rule

$policy = @"
{
    "arn": [
        "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
}
"@
## $((Get-STSCallerIdentity).Account) returns the current AWS account number
## Replace ROLE-Name with any name you'd like the role to be
Write-S3Object -BucketName $bucket.BucketName -Key "$((Get-STSCallerIdentity).Account)/ROLE-Name/managed.json" -Content $policy
$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
"@
Write-S3Object -BucketName $bucket.BucketName -Key "$((Get-STSCallerIdentity).Account)/ROLE-Name/inline/POLICY-FullAdmin.json" -Content $policy

Invoke-LMFunction -FunctionName $lambda.FunctionName
Get-IAMRole -RoleName "ROLE-Name"
