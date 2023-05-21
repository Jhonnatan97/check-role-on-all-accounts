import boto3
import json
from botocore.exceptions import ClientError

boto3.setup_default_session (profile_name='profile_name')
session = boto3.Session (profile_name='profile_name')

organizations = session.client ('organizations')
iam = boto3.client ('iam')
dynamodb = boto3.client ('dynamodb', region_name='us-east-1')

account_suspended = []
account_active = []

accounts = []
accounts_prd = []
another_accounts = []

assume_role_policy_document = json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": [
                                "arn:aws:iam::{ID_ACCOUNT}:root",
                                "arn:aws:iam::{ID_ACCOUNT}:root"
                            ]
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            })
my_managed_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:PutItem",
                            "dynamodb:DescribeTable",
                            "dynamodb:GetItem",
                            "dynamodb:DeleteItem"
                        ],
                        "Resource": "{ARN_TABLE}"
                    },
                    {
                        "Sid": "VisualEditor1",
                        "Effect": "Allow",
                        "Action": [
                            "iam:DeleteAccessKey",
                            "dynamodb:ListTables",
                            "secretsmanager:PutSecretValue",
                            "secretsmanager:CreateSecret",
                            "iam:UpdateAccessKey",
                            "secretsmanager:UpdateSecret",
                            "iam:CreateAccessKey",
                            "secretsmanager:GetSecretValue",
                            "iam:ListUsers",
                            "iam:GetUser",
                            "secretsmanager:ListSecrets",
                            "iam:ListUserTags",
                            "iam:ListAccessKeys",
                            "organizations:ListAccounts"
                        ],
                        "Resource": "*"
                    }
                ]
            }

def main():
    users = []
    accounts = []

    response = organizations.list_accounts ()
    accounts.extend (response['Accounts'])
    while 'NextToken' in response.keys ():
        response = organizations.list_accounts (NextToken=response['NextToken'])
        accounts.extend (response['Accounts'])
    print ('accounts found: ' + str (len (accounts)))


    for i in accounts:
        id_account = i['Id']
        status = i['Status']
        name = i['Name']
        if status == 'SUSPENDED':
            account_suspended.append ({"Name": name, "id_account": id_account, "Status": status})
        else:
            account_active.append ({"Name": name, "id_account": id_account, "Status": status})

    for contas in account_active:
        account_prd = contas['Name']
        if '-prd' in account_prd:
            accounts_prd.append (account_prd)
        else:
            another_accounts.append (account_prd)


    for account in account_active:
        print ()
        id_account_name = str(account['Name'])
        id_account_id = str(account['id_account'])
        print ('Account:', account['Name'], 'Id:', account['id_account'])

        credentials = session.get_credentials ()
        sts = session.client ('sts')
        assume_role_response = sts.assume_role (
            RoleArn=f"arn:aws:iam::{account['id_account']}:role/{arn_role}",
            RoleSessionName="AssumeRoleSession1"
        )
        temp_session = boto3.Session (
            aws_access_key_id=assume_role_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=assume_role_response['Credentials']['SecretAccessKey'],
            aws_session_token=assume_role_response['Credentials']['SessionToken']
        )

        iam = temp_session.client('iam')
        response = iam.get_role(RoleName='role_name')['Role']
        print('Role existe: ',response['RoleName'])
        try:
            response = iam.get_role(RoleName='role_name')['Role']
            print(f"Role {response['RoleName']} já existe em conta {account}")

        except ClientError as e:
            # Cria a role lambda-infosec com permissão inline se ela não existe
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print(f"Role name não existe em conta {account}, criando agora...")
                iam.create_role(RoleName='role-name', AssumeRolePolicyDocument=assume_role_policy_document)
                iam.put_role_policy(RoleName='role-name', PolicyName='role-name-inline', PolicyDocument=json.dumps(my_managed_policy))
                print(f"Role {response['RoleName']} criada com permissão inline em conta {account}")
            else:
                print(f"Erro ao verificar role XXXXX em conta {account}: {e}")

        except ClientError as e:
            print (f"Erro ao assumir a role Admin em conta {account}: {e}")



if __name__ == '__main__':
    main()