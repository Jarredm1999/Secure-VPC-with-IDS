# AWS Cloud Security & Networking Project: Secure VPC Design & Intrusion Detection System

![final-vpc-diagram](link to pic)

## Summary
This lab demonstrates the deployment and configuration of a secure, multi-tier AWS network architecture with an integration intrusion detection system (IDS). The primary goal was to build hands on experience in AWS networking, security groups, network ACLs, bastion host configuration, VPC Flow Logs, and CloudWatch monitoring, while showcasing practical cloud security skills relevant for cloud engineering and cybersecurity roles.

### Lab Architecture
- VPC with public and private subnets.
- Bastion Host in public subnet for secure SSH access to private instances.
- NAT Gateway to allow outbound Internet access from private subnet. 
- Private Application Server in private subnet.
- Security Controls:
   - Security Groups(SG)
   - Network ACLs(NACL)
   - VPC Flow Logs for monitoring traffic
- CloudWatch Metrics & Alarms to detect suspicious activity.


