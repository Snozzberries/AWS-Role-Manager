$bucket = New-S3Bucket -BucketName "awslambdapowershelldemo"
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

$function = @"
#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.0.2.0'}, @{ModuleName='AWS.Tools.S3';ModuleVersion='4.0.2.0'}, @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.0.2.0'}
# Select all the objects within the central configuration bucket
`$objects = Get-S3Object -BucketName $($bucket.BucketName)
foreach(`$object in `$objects)
{
    # You will use parts of the object paths later in the function so we will identify those pieces	 
    # Determine the index of the first forward slash
    `$firstSlash = `$object.Key.IndexOf("/")
    # Determine the index of the second forward slash
    `$secondSlash = `$object.Key.IndexOf("/",`$firstSlash+1)-`$firstSlash-1
    # The entity represents the AWS account number or the AWS service name the role is for
    `$entity = `$object.Key.Substring(0,`$firstSlash)
    # The role name will be used for the actual IAM Role Name
    `$roleName = `$object.Key.Substring(`$firstSlash+1,`$secondSlash)
    # The policy name will be used to name the customer managed policies
    `$policyName = `$object.Key.Substring(`$firstSlash+`$secondSlash+2,`$object.Key.IndexOf(".")-`$firstSlash-`$secondSlash-2)
    # We first identify if the entity is an AWS account number, essentially 12 digits
    if(`$entity -match "^[0-9]{12}$")
    {
        `$policy = @`"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "`$entity"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
`"@
        # Create the new role
        `$role = New-IAMRole -RoleName "`$roleName" -AssumeRolePolicyDocument `$policy
    }
    # We assume if it isn't an account number, then it is intended to be an AWS service name
    else
    {
        `$policy = @`"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "`$entity.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
`"@
        `$role = New-IAMRole -RoleName "`$roleName" -AssumeRolePolicyDocument `$policy
    }
    # Next we need to idnetify AWS or customer managed policies to attach to the role
    # A managed object name will refer to AWS managed
    if(`$policyName -eq "managed")
    {
        # First download the policy object
        `$file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName $($bucket.BucketName) -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "`$entity/`$roleName/`$policyName.json")
        # Next get the content from the downloaded object
        `$json = [System.Text.Encoding]::ASCII.GetString(`$file.content)
        # Then convert it to a JSON object
        `$jsonObject = ConvertFrom-Json `$json
        foreach(`$arn in `$jsonObject.arn)
        {
            # Now for each of the ARNs attach them to the Role
            Register-IAMRolePolicy -RoleName "`$roleName" -PolicyArn "`$arn"
        }
    }
    # We assume everything else is a unique customer managed policy
    else
    {
        `$file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName $($bucket.BucketName) -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "`$entity/`$roleName/`$policyName.json")
        `$json = [System.Text.Encoding]::ASCII.GetString(`$file.content)
        # Create the new IAM Policy and attach to the Role
        Write-IAMRolePolicy -RoleName "`$roleName" -PolicyDocument `$json -PolicyName `$policyName
    }
}
"@

Set-Content .\FUNCTION-RoleManager-1\FUNCTION-RoleManager-1.ps1 -Value $function

Publish-AWSPowerShellLambda -ScriptPath .\FUNCTION-RoleManager-1\FUNCTION-RoleManager-1.ps1 -Name FUNCTION-RoleManager-1 -Region us-west-2 -IAMRoleArn $role.Arn

$lambda = Get-LMFunctionList|Where-Object{$_.Role -eq $role.Arn}
$rule = Write-CWERule -Name "RULE-CronHourly" -ScheduleExpression "rate(1 hour)" -State ENABLED
$target = New-Object Amazon.CloudWatchEvents.Model.Target
$target.Arn = $lambda.FunctionArn
$target.Id = $lambda.RevisionId
Write-CWETarget -Rule $rule.Substring($rule.IndexOf("/")+1) -Target $target
Add-LMPermission -FunctionName $lambda.FunctionName -Action "lambda:InvokeFunction" -Principal "events.amazonaws.com" -StatementId $rule.Substring($rule.IndexOf("/")+1) -SourceArn $rule

<# Example Roles
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
#>
