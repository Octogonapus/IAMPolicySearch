# IAMPolicySearch

Search for IAM policies by the permission they grant, instead of by their name.

## Examples

Find that pesky inline policy allowing access to a secret without having to manually search through multiple users:

```sh
$ go run main.go 'secretsmanager:GetSecretValue' 'arn:aws:secretsmanager:us-east-2:1234567890:secret:rds-db-credentials/primary/mydb'
The action secretsmanager:GetSecretValue on the resource arn:aws:secretsmanager:us-east-2:1234567890:secret:rds-db-credentials/primary/mydb is allowed by the following policies:
(user inline policy) UserName=SomeUser PolicyName=inline
Arn=arn:aws:iam::1234567890:policy/some-other-policy VersionId=v5
        is attached to role: Name=some-other-policy Id=SAND902N0F20
```

See what can access your S3 bucket:

```sh
$ go run main.go 's3:GetObject' 'arn:aws:s3:::my-bucket/prefix/*'                                                                          
The action s3:GetObject on the resource arn:aws:s3:::my-bucket/prefix/* is allowed by the following policies:
Arn=arn:aws:iam::1234567890:policy/Policy1 VersionId=v17
        is attached to group: Name=Group1 Id=SAND902N0F20
Arn=arn:aws:iam::1234567890:policy/Policy1 VersionId=v16
        is attached to group: Name=Group1 Id=SAND902N0F20
Arn=arn:aws:iam::1234567890:policy/Policy2 VersionId=v1
        is attached to role: Name=Role1 Id=SAND902N0F21
        is attached to role: Name=Role2 Id=SAND902N0F22
```
