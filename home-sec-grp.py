#!/usr/bin/python
# This script is to update my security group with my current Public IP.
# You will need Boto3 for this to work.

__author__ = 'Jayakrishnan L.'


import boto3
import urllib2



# Find out my Public IP
resp = urllib2.urlopen('http://checkip.amazonaws.com')
ip = resp.read()
myip = ip.rstrip('\n') + '/' + '32'
print 'My current Public IP is: ', myip


ec2 = boto3.resource('ec2')
security_group = ec2.SecurityGroup('sg-d3e304b5')

print 'Name of the Security Group is: ', security_group.group_name, 'and it has ID: ', security_group.group_id


ip_permissions = security_group.ip_permissions


print 'Current Rules'
for rules in ip_permissions:
    print rules


for rules in ip_permissions:
    if rules['IpProtocol'] == 'tcp' and rules['ToPort'] == 22:
        for cidr in rules['IpRanges']:
            if cidr['CidrIp'] != myip:
                print ('\nLets remove those old IPs: ' + cidr['CidrIp'] + '\n')
                try:
                    print(security_group.revoke_ingress(
                        DryRun=False,
                        IpProtocol=rules['IpProtocol'],
                        FromPort=rules['FromPort'],
                        ToPort=rules['ToPort'],
                        CidrIp=cidr['CidrIp']
                    ))
                except Exception as e:
                    print(e)

print '\nNow lets add rules for current Public IP:', myip, '\n'

try:
    print(security_group.authorize_ingress(
        DryRun=False,
        IpProtocol='tcp',
        FromPort=22,
        ToPort=22,
        CidrIp=myip
    ))
except Exception as e:
    print(e)
