import boto3
import os
import traceback
import json
from botocore.exceptions import ClientError
import time
import credentials


global_var_json = {
}


def addUserDataVars(UserDataFile):
    file = open(UserDataFile, 'r')

    userData = ''
    line = file.readline()
    while line:
        new_line = line
        if new_line and len(new_line) > 1:
            for key, value in global_var_json.items():
                if key in new_line and value:
                    new_line = new_line.replace(key, value)

        userData += new_line
        line = file.readline()

    return userData


def new_key_pair(client, KeyName):
    client.delete_key_pair(KeyName=KeyName)

    key_pair = client.create_key_pair(KeyName=KeyName)
    try:
        os.chmod(f'./{KeyName}.pem', 0o777)
    except Exception:
        pass

    with open(f'./{KeyName}.pem', 'w+') as text_file:
        text_file.write(key_pair['KeyMaterial'])
        print(f'Chave: {KeyName} criada')

    os.chmod(f'./{KeyName}.pem', 0o400)


def delete_security_group(client, resource, GroupName):
    try:
        client.delete_security_group(GroupName=GroupName, DryRun=False)
    except ClientError as e:
        print(f'[ERROR] - delete_security_group: {e}')


def create_security_group(client, resource, config):
    GroupName = config.get('GroupName')
    Description = config.get('Description')
    ingress_rules = config.get('ingress_rules')

    describe_vpcs = client.describe_vpcs()
    VpcId = describe_vpcs['Vpcs'][0]['VpcId']

    delete_security_group(client, resource, GroupName)
    try:
        resource.create_security_group(
            GroupName=GroupName,
            Description=Description,
            VpcId=VpcId
        )

        print(f'SecurityGroup: {GroupName} criado')

        SecurityGroup = resource.SecurityGroup('id')

        for rule in ingress_rules:
            SecurityGroup.authorize_ingress(
                GroupName=GroupName,
                IpProtocol=rule['IpProtocol'],
                CidrIp=rule['CidrIp'],
                FromPort=rule['FromPort'],
                ToPort=rule['ToPort'],
            )
    except ClientError as e:
        print(f'[ERROR] - resource.create_security_group: {e}')


# Para testar o postgres
# psql -U cloud -d tasks -h localhost

def wait_instances(waiter, client, instances_ids):
    client.get_waiter(waiter).wait(InstanceIds=instances_ids)
    return client.describe_instances(InstanceIds=instances_ids)


def terminate_instance(resource, client, InstanceIds=[]):
    response = {}
    if InstanceIds:
        response = client.describe_instances(InstanceIds=InstanceIds)
    else:
        response = client.describe_instances()

    instances_ids = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            InstanceId = instance['InstanceId']
            if InstanceId:
                print(f'deleting instance: {InstanceId}')
                resource.Instance(InstanceId).terminate()
                instances_ids.append(InstanceId)
                wait_instances('instance_terminated', client, [InstanceId])
    print(f'instance_terminated: {len(instances_ids)}')


def create_new_instance(resource, client, config):
    if config:
        ImageId = config.get('ImageId')
        MinCount = config.get('MinCount')
        MaxCount = config.get('MaxCount')
        InstanceType = config.get('InstanceType')
        KeyName = config.get('KeyName')
        SecurityGroups = config.get('SecurityGroups')
        TagSpecifications = config.get('TagSpecifications')
        UserDataFile = config.get('UserDataFile')
        UserDataReplaceVars = config.get('UserDataReplaceVars')
        createImage = config.get('createImage', False)

        UserData = ''
        if UserDataFile:
            UserData = open(UserDataFile, 'r').read()
            if UserDataReplaceVars and len(UserDataReplaceVars) > 0:
                UserData = addUserDataVars(UserDataFile)
                print(f'UserData: {UserData}')

        instanceName = ''
        if TagSpecifications:
            instanceName = TagSpecifications[0]['Tags'][0]['Value']

        print(f'Criando instancia: {instanceName}')
        try:
            [new_instance] = resource.create_instances(
                ImageId=ImageId,
                MinCount=MinCount,
                MaxCount=MaxCount,
                InstanceType=InstanceType,
                KeyName=KeyName,
                SecurityGroups=SecurityGroups,
                UserData=UserData,
                TagSpecifications=TagSpecifications,
            )

            new_instance_id = new_instance.instance_id
            wait_instances('instance_status_ok', client, [new_instance_id])
            print(f'Criou instancia: {new_instance_id}')
        except ClientError as e:
            print(f'[ERROR]: {e}')

        image_id = ''
        try:
            if createImage:
                image_id = create_image_from_instance_id(
                    client, new_instance_id, f'{instanceName}-{new_instance_id}')

        except ClientError as e:
            print(f'[ERROR]: {e}')

        return [new_instance_id, image_id, instanceName]


def get_instance_ip(client, instance_id):
    response = client.describe_instances(InstanceIds=[instance_id])

    if len(response['Reservations']) > 0:
        instance_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        return instance_ip
    else:
        print('[LOG] Error getting DB IP address.')


def delete_autoscaling_by_name(as_client, name):
    try:
        as_client.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True)
        print(f'Autoscaling deletado: {name}')
        as_client.delete_launch_configuration(LaunchConfigurationName=name)
        print(f'launch_configuration deletado: {name}')
    except ClientError as e:
        print(e)


def delete_load_balancers(elb_client, name):
    print(f'[LOG] Deleting LB...')

    response = elb_client.describe_load_balancers()

    for load_balancer in response['LoadBalancers']:
        if load_balancer['LoadBalancerName'] == name:
            elb_client.delete_load_balancer(LoadBalancerName=name)

            elb_client.get_waiter('load_balancers_deleted').wait(Names=[name])
            print(f'load balancer deletado: {name}')
        else:
            print('load balancer não encontrado: {name}')


def create_load_balancer(ec2_client, elb_client, config):
    Name = config.get('Name', '')
    delete_load_balancers(elb_client, Name)

    SecurityGroupName = config.get('SecurityGroupName', '')
    Tags = config.get('Tags', [])
    Scheme = config.get('Scheme', [])

    security_group = ec2_client.describe_security_groups(
        GroupNames=[SecurityGroupName])
    security_group_id = security_group['SecurityGroups'][0]['GroupId']

    response = ec2_client.describe_subnets()
    subnets = []
    for subnet in response['Subnets']:
        subnets.append(subnet['SubnetId'])

    print(f'Criando load balancer: {Name}')
    response = elb_client.create_load_balancer(
        Name=Name,
        Subnets=subnets,
        SecurityGroups=[security_group_id],
        Scheme=Scheme,
        Tags=Tags
    )

    LoadBalancerArn = response['LoadBalancers'][0]['LoadBalancerArn']
    LoadBalancerDNS = response['DNSName']
    print(f'LoadBalancerDNS: {LoadBalancerDNS}')

    with open("loadBalancer_DNS.txt", "w+") as file:
        file.write(LoadBalancerDNS)
        
    elb_client.get_waiter('load_balancer_available').wait(
        LoadBalancerArns=[LoadBalancerArn])
    print(f'Load balancer criado: {LoadBalancerArn}')
    return LoadBalancerArn


def create_target_groups(ec2_client, elb_client, VpcId, groupConfig):
    try:
        Name = groupConfig.get('Name')
        Protocol = groupConfig.get('Protocol')
        Port = groupConfig.get('Port')
        HealthCheckProtocol = groupConfig.get('HealthCheckProtocol')
        HealthCheckPath = groupConfig.get('HealthCheckPath')
        TargetType = groupConfig.get('TargetType')
        print(f'Criando target group: {Name}')
        response = elb_client.create_target_group(
            Name=Name,
            Protocol=Protocol,
            Port=Port,
            VpcId=VpcId,
            HealthCheckProtocol=HealthCheckProtocol,
            HealthCheckPath=HealthCheckPath,
            TargetType=TargetType,
        )

        TargetGroupArn = response['TargetGroups'][0]['TargetGroupArn']

        print(f'target group criado: {TargetGroupArn}')
        return TargetGroupArn
    except ClientError as error:
        print(f'[ERROR]: {error}')

    return


def findTargetGroupArnByName(elb_client, name):
    target_groups = elb_client.describe_target_groups()
    for target_group in target_groups['TargetGroups']:
        if target_group['TargetGroupArn'] and target_group['TargetGroupName'] == name:
            return target_group['TargetGroupArn']


def create_listener(elb_client, config):
    try:
        Protocol = config.get('Protocol')
        Port = config.get('Port')
        LoadBalancerName = config.get('LoadBalancerArn', [])

        DefaultActions = config.get('DefaultActions', [])
        NewDefaultActions = []
        if DefaultActions and len(DefaultActions) > 0:
            target_groups = elb_client.describe_target_groups()

            for action in DefaultActions:
                if 'TargetGroupArn' in action:
                    for target_group in target_groups['TargetGroups']:
                        if target_group['TargetGroupArn'] and target_group['TargetGroupName'] == action['TargetGroupArn']:
                            action['TargetGroupArn'] = target_group['TargetGroupArn']

                NewDefaultActions.append(action)

        NewLoadBalancerArn = LoadBalancerName
        if NewLoadBalancerArn:
            load_balancers = elb_client.describe_load_balancers()[
                'LoadBalancers']

            for load_balancer in load_balancers:
                print(load_balancer)
                if load_balancer['LoadBalancerName'] == LoadBalancerName:
                    if load_balancer['LoadBalancerArn']:
                        NewLoadBalancerArn = load_balancer['LoadBalancerArn']

        print(f'Criando listener:\nLoadBalancerArn: {NewLoadBalancerArn}')
        elb_client.create_listener(
            LoadBalancerArn=NewLoadBalancerArn,
            Protocol=Protocol,
            Port=Port,
            DefaultActions=NewDefaultActions
        )
        print(f'listener criado\n')

    except ClientError as e:
        print(f'[ERROR]: {e}')


def create_auto_scaling(ec2_client, elb_client, as_client, instances, config):
    try:
        AutoScalingGroupName = config.get('AutoScalingGroupName')
        if AutoScalingGroupName:
            delete_autoscaling_by_name(as_client, AutoScalingGroupName)

        MinSize = config.get('MinSize')
        MaxSize = config.get('MaxSize')
        DesiredCapacity = config.get('DesiredCapacity')
        Tags = config.get('Tags')

        TargetGroupARNs = config.get('TargetGroupARNs')
        NewTargetGroupARNs = []
        for name in TargetGroupARNs:
            TargetGroupARN = findTargetGroupArnByName(elb_client, name)
            NewTargetGroupARNs.append(TargetGroupARN)

        InstanceName = config.get('InstanceName')
        InstanceId = ''
        for instance in instances:
            if instance['name'] == InstanceName:
                InstanceId = instance['id']

        print(f'Criando auto scalling group: {AutoScalingGroupName}')
        as_client.create_auto_scaling_group(
            AutoScalingGroupName=AutoScalingGroupName,
            MinSize=MinSize,
            MaxSize=MaxSize,
            DesiredCapacity=DesiredCapacity,
            Tags=Tags,
            TargetGroupARNs=NewTargetGroupARNs,
            InstanceId=InstanceId
        )
        print(f'auto scalling group criado: {AutoScalingGroupName}')

    except ClientError as e:
        print(f'[ERROR]: {e}')


def loadConfigJson():
    json_file_path = './config.json'
    contents = {}
    with open(json_file_path, 'r') as j:
        contents = json.loads(j.read())
    return contents


def create_image_from_instance_id(client, InstanceId, Name):
    print(f'Criando image [{Name}] apartir de [{InstanceId}]')
    image = client.create_image(
        InstanceId=InstanceId, NoReboot=True, Name=Name)
    client.get_waiter('image_available').wait()
    imageId = image['ImageId']
    print(f'Imagem {imageId} criada')
    return imageId


def runAll(region_name, configJson):
    session = boto3.session.Session(
        aws_access_key_id=credentials.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=credentials.AWS_SECRET_ACCESS_KEY,
        region_name=region_name
    )

    ec2_resource = session.resource('ec2')
    ec2_client = session.client('ec2')
    elb_client = session.client('elbv2')
    as_client = session.client('autoscaling')

    config = configJson[region_name]

    KeyName = config.get('KeyName')

    new_key_pair(ec2_client, KeyName)

    terminate_instance(ec2_resource, ec2_client)
    SecurityGroupsConfig = config.get('SecurityGroups', [])

    for SecurityGroup in SecurityGroupsConfig:
        create_security_group(ec2_client, ec2_resource, SecurityGroup)

    instances = []

    instancesConfig = config.get('instances', [])
    for instanceConfig in instancesConfig:
        [instance_id, image_id, instanceName] = create_new_instance(
            ec2_resource, ec2_client, instanceConfig)
        instance_ip = get_instance_ip(ec2_client, instance_id)
        instanceData = {
            'id': instance_id,
            'ip': instance_ip,
            'name': instanceName
        }
        if image_id:
            instanceData['image_id'] = image_id

        instances.append(instanceData)

    loadBalancersConfigs = config.get('loadBalancers', [])
    for loadBalancerConfig in loadBalancersConfigs:
        create_load_balancer(ec2_client, elb_client, loadBalancerConfig)

    describe_vpcs = ec2_client.describe_vpcs()
    VpcId = describe_vpcs['Vpcs'][0]['VpcId']
    targetGroupsConfigs = config.get('targetGroups', [])
    targetGroups = []
    for groupConfig in targetGroupsConfigs:
        targetGroupArn = create_target_groups(
            ec2_client, elb_client, VpcId, groupConfig)
        if targetGroupArn:
            targetGroups.append(targetGroupArn)

    listenersConfigs = config.get('listeners', [])
    for listenerConfig in listenersConfigs:
        create_listener(elb_client, listenerConfig)

    autoscalingsConfigs = config.get('autoscalings', [])
    for autoscalingConfig in autoscalingsConfigs:
        create_auto_scaling(ec2_client, elb_client,
                            as_client, instances, autoscalingConfig)
    print(f'instances: {instances}')
    return instances


configJson = loadConfigJson()
us_east_2_instances = runAll('us-east-2', configJson)
print(us_east_2_instances)
db_ip = us_east_2_instances[0]['ip']
print(db_ip)
global_var_json['DB_IP'] = db_ip

us_east_1_instances = runAll('us-east-1', configJson)
