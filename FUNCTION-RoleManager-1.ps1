#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.0.2.0'}, @{ModuleName='AWS.Tools.S3';ModuleVersion='4.0.2.0'}, @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.0.2.0'}
# Select all the objects within the central configuration bucket
$objects = Get-S3Object -BucketName "awslambdapowershelldemo1" # $($bucket.BucketName)
foreach($object in $objects) {
    # You will use parts of the object paths later in the function so we will identify those pieces	 
    # Determine the index of the first forward slash
    $firstSlash = $object.Key.IndexOf("/")
    # Determine the index of the second forward slash
    $secondSlash = $object.Key.IndexOf("/", $firstSlash+1)-$firstSlash-1
    # The entity represents the AWS account number or the AWS service name the role is for
    $entity = $object.Key.Substring(0, $firstSlash)
    # The role name will be used for the actual IAM Role Name
    $roleName = $object.Key.Substring($firstSlash+1, $secondSlash)
    # The policy name will be used to name the customer managed policies
    $policyName = $object.Key.Substring($firstSlash+$secondSlash+2, $object.Key.IndexOf(".")-$firstSlash-$secondSlash-2)
    # We first identify if the entity is an AWS account number, essentially 12 digits
    if($entity -match "^[0-9]{12}$") {
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
        # Create the new role
        $role = New-IAMRole -RoleName "$roleName" -AssumeRolePolicyDocument $policy
    }
    # We assume if it isn't an account number, then it is intended to be an AWS service name
    else {
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
    # Next we need to idnetify AWS or customer managed policies to attach to the role
    # A managed object name will refer to AWS managed
    if($policyName -eq "managed") {
        # First download the policy object
        $file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName "awslambdapowershelldemo" <#$($bucket.BucketName)#> -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "$entity/$roleName/$policyName.json")
        # Next get the content from the downloaded object
        $json = [System.Text.Encoding]::ASCII.GetString($file.content)
        # Then convert it to a JSON object
        $jsonObject = ConvertFrom-Json $json
        foreach($arn in $jsonObject.arn) {
            # Now for each of the ARNs attach them to the Role
            Register-IAMRolePolicy -RoleName "$roleName" -PolicyArn "$arn"
        }
    }
    # We assume everything else is a unique customer managed policy
    else {
        $file = Invoke-WebRequest (Get-S3PreSignedURL -BucketName "awslambdapowershelldemo" <#$($bucket.BucketName)#> -Expire (Get-Date).AddMinutes(1) -Protocol HTTP -Key "$entity/$roleName/$policyName.json")
        $json = [System.Text.Encoding]::ASCII.GetString($file.content)
        # Create the new IAM Policy and attach to the Role
        Write-IAMRolePolicy -RoleName "$roleName" -PolicyDocument $json -PolicyName "$policyName"
    }
}
