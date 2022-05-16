# Make a new bucket
$bucket = New-S3Bucket -BucketName "ops-iamroles"
# Block public access
Add-S3PublicAccessBlock -BucketName $bucket.BucketName -PublicAccessBlockConfiguration_BlockPublicAcl $true -PublicAccessBlockConfiguration_BlockPublicPolicy $true -PublicAccessBlockConfiguration_IgnorePublicAcl $true -PublicAccessBlockConfiguration_RestrictPublicBucket $true
# Enable versioning
Write-S3BucketVersioning -BucketName $bucket.BucketName -VersioningConfig_Status "Enabled"
# Lambda Role
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
# New-IAMRole for Lambda function
$role = New-IAMRole -RoleName "ROLE-RoleManager" -AssumeRolePolicyDocument $policy
# Bucket Policy
$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::615717400922:role/ROLE-RoleManager"
                ]
            },
            "Action": [
                "s3:*"
            ],
            "Resource": [
                "arn:aws:s3:::ops-iamroles",
                "arn:aws:s3:::ops-iamroles/*"
            ]
        }
    ]
}
"@
# Write the bucket policy for the Lambda Roles
Write-S3BucketPolicy -BucketName $bucket.BucketName -Policy $policy
# Inline Policy
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
# Write-IAMRolePolicy - Inline
Write-IAMRolePolicy -RoleName "ROLE-RoleManager" -PolicyDocument $policy -PolicyName "POLICY-ROLE-RoleManager"
# Register-IAMRolePolicy - Managed
Register-IAMRolePolicy -RoleName "ROLE-RoleManager" -PolicyArn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
# Create a Lambda function template
New-AWSPowerShellLambda -ScriptName FUNCTION-RoleManager-1 -Template Basic
# The Lambda Function
$function = @"
$objects = Get-S3Object -BucketName $bucket.BucketName
foreach($object in $objects)
{
    $firstSlash = $object.Key.IndexOf("/")
    $secondSlash = $object.Key.IndexOf("/",$firstSlash+1)-$firstSlash-1
    $entity = $object.Key.Substring(0,$firstSlash)
    $roleName = $object.Key.Substring($firstSlash+1,$secondSlash)
    $policyName = $object.Key.Substring($firstSlash+$secondSlash+2,$object.Key.IndexOf(".")-$firstSlash-$secondSlash-2)
    if($entity -match "^[0-9]{12}$")
    {
        $policy = @'
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
        '@
        $role = New-IAMRole -RoleName "$roleName" -AssumeRolePolicyDocument $policy
    }
    else
    {
        $policy = @'
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
        '@
        $role = New-IAMRole -RoleName "$roleName" -AssumeRolePolicyDocument $policy
    }
    if($policyName -eq "managed")
    {
        $file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName $bucket.BucketName -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "$entity/$roleName/$policyName.json")
        $json = [System.Text.Encoding]::ASCII.GetString($file.content)
        $jsonObject = ConvertFrom-Json $json
        foreach($arn in $jsonObject.arn)
        {
            Register-IAMRolePolicy -RoleName "$roleName" -PolicyArn "$arn"
        }
    }
    else
    {
        $file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName $bucket.BucketName -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "$entity/$roleName/$policyName.json")
        $json = [System.Text.Encoding]::ASCII.GetString($file.content)
        Write-IAMRolePolicy -RoleName "$roleName" -PolicyDocument $json -PolicyName "$policyName"
    }
}
"@
# Append to the Lambda Function file
Add-Content C:\FUNCTION-RoleManager-1\FUNCTION-RoleManager-1.ps1 -Value $function
# Publish Lambda Function to AWS
Publish-AWSPowerShellLambda -ScriptPath C:\FUNCTION-RoleManager-1\FUNCTION-RoleManager-1.ps1 -Name FUNCTION-RoleManager-1 -Region us-west-2 -IAMRoleArn $role.Arn
# Get Lambda Function
$lambda = Get-LMFunctionList|Where-Object{$_.Role -eq $role.Arn}
# Create a CWE Rule
$rule = Write-CWERule -Name "RULE-CronHourly" -ScheduleExpression "rate(1 hour)" -State ENABLED
# New CWE Target
$target = New-Object Amazon.CloudWatchEvents.Model.Target
$target.Arn = $lambda.FunctionArn
$target.Id = $lambda.RevisionId
# Create the Target
Write-CWETarget -Rule $rule.Substring($rule.IndexOf("/")+1) -Target $target
######
######
######
# Create a json to hold the managed policy ARNs
$policy = @"
{
    "arn": [
        "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
}
"@
# Put the managed policies in a json file
Write-S3Object -BucketName $bucket.BucketName -Key "service|account/ROLE-Name/managed.json" -Content $policy
# Create an inline policy json
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
# Put policy json to S3
Write-S3Object -BucketName $bucket.BucketName -Key "ROLE-Name/inline/POLICY-FullAdmin.json" -Content $policy
# Manually invoke Lambda
Invoke-LMFunction -FunctionName $lambda.FunctionName
# Validate new Role
Get-IAMRole -RoleName "ROLE-Name"
