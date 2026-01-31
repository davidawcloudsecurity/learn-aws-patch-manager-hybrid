terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}
provider "aws" {
  region = "us-east-1"
}

# Create instance in one of the subnet
resource "aws_instance" "dev-instance-windows-master" {
  ami                         = "ami-0f73246b6299f4858"
  instance_type               = "t3.large"
  availability_zone           = "us-east-1a"
  tenancy                     = "default"
  subnet_id                   = aws_subnet.terraform-public-subnet-master.id # Public Subnet A
  ebs_optimized               = false
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
  vpc_security_group_ids = [
    aws_security_group.terraform-public-facing-db-sg-master.id # public-facing-security-group
  ]
  source_dest_check = true
  root_block_device {
    volume_type           = "gp2"
    delete_on_termination = true
  }
  user_data = <<EOF
<powershell>
# Basic Windows configuration
Write-Host "Configuring Windows instance..."

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Set timezone
Set-TimeZone -Id "Eastern Standard Time"

Write-Host "Windows configuration completed."
</powershell>
EOF

  tags = {
    Name = "dev-instance-windows-terraform-master"
  }
}

# Create instance in private subnet to simulate on-premise server
resource "aws_instance" "dev-instance-windows-slave" {
  ami                         = "ami-0f73246b6299f4858"
  instance_type               = "t3.large"
  availability_zone           = "us-east-1b"
  tenancy                     = "default"
  subnet_id                   = aws_subnet.terraform-private-subnet-slave.id # Private Subnet - simulating on-premise
  ebs_optimized               = false
  associate_public_ip_address = false # No public IP - simulating on-premise
  vpc_security_group_ids = [
    aws_security_group.terraform-db-sg-slave.id # private-facing-security-group
  ]
  source_dest_check = true
  root_block_device {
    volume_type           = "gp2"
    delete_on_termination = true
  }
  user_data = <<EOF
<powershell>
# Basic Windows configuration for on-premise simulation
Write-Host "Configuring Windows instance as on-premise simulation..."

# Create local user ec2-user with password
$Password = ConvertTo-SecureString "Letmein2021" -AsPlainText -Force
New-LocalUser "ec2-user" -Password $Password -FullName "EC2 User" -Description "Local user for on-premise simulation"
Add-LocalGroupMember -Group "Administrators" -Member "ec2-user"

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Set timezone
Set-TimeZone -Id "Eastern Standard Time"

Write-Host "On-premise simulation configuration completed."
Write-Host "User: ec2-user | Password: Letmein2021"
Write-Host "This instance has no direct internet access - use SSM hybrid activation for management"
</powershell>
EOF

  tags = {
    Name = "dev-instance-windows-terraform-slave-onpremise"
  }
}

# VPC Peering
resource "aws_vpc_peering_connection" "default-peering-slave" {
  # peer_owner_id = var.peer_owner_id
  peer_vpc_id   = aws_vpc.terraform-default-vpc-master.id
  vpc_id        = aws_vpc.terraform-default-vpc-slave.id
  auto_accept   = true
  tags = {
    Name = "VPC Peering between master and slave"
  }
}

resource "aws_vpc" "terraform-default-vpc-master" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "learn-terraform-vpc-master"
  }
}

resource "aws_vpc" "terraform-default-vpc-slave" {
  cidr_block           = "172.16.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "learn-terraform-vpc-slave-onpremise"
  }
}

# How to create public / private subnet
resource "aws_subnet" "terraform-public-subnet-master" {
  vpc_id            = aws_vpc.terraform-default-vpc-master.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "terraform-public-subnet--master-A"
  }
}

resource "aws_subnet" "terraform-private-subnet-master" {
  vpc_id            = aws_vpc.terraform-default-vpc-master.id
  cidr_block        = "10.10.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "terrform-private-subnet-master-A"
  }
}

# How to create public / private subnet
resource "aws_subnet" "terraform-public-subnet-slave" {
  vpc_id            = aws_vpc.terraform-default-vpc-slave.id
  cidr_block        = "172.16.1.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "terraform-public-subnet-slave-B"
  }
}

resource "aws_subnet" "terraform-private-subnet-slave" {
  vpc_id            = aws_vpc.terraform-default-vpc-slave.id
  cidr_block        = "172.16.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "terrform-private-subnet-slave-B-onpremise"
  }
}

# How to create custom route table
resource "aws_route_table" "terraform-public-route-table-master" {
  vpc_id = aws_vpc.terraform-default-vpc-master.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.terraform-default-igw-master.id
  }
  route {
    cidr_block    = aws_vpc.terraform-default-vpc-slave.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.default-peering-slave.id   
  }
    
  tags = {
    Name = "terraform-public-route-table-master"
  }
}

resource "aws_route_table" "terraform-private-route-table-master" {
  vpc_id = aws_vpc.terraform-default-vpc-master.id

  # Comment this out to cut cost and focus on igw only
  /*
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.terraform-ngw.id
  }
*/
  tags = {
    Name = "terraform-private-route-table-master"
  }
}

# How to create custom route table
resource "aws_route_table" "terraform-public-route-table-slave" {
  vpc_id = aws_vpc.terraform-default-vpc-slave.id
  route {
    cidr_block = "0.0.0.0/0"
    vpc_peering_connection_id = aws_vpc_peering_connection.default-peering-slave.id 
  }
  route {
    cidr_block = aws_vpc.terraform-default-vpc-master.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.default-peering-slave.id 
  }

  tags = {
    Name = "terraform-public-route-table-slave"
  }
}

/*
# This append the vpc peering connection to the master route table
resource "aws_route" "route-vpc-peering-master" {
  route_table_id            = aws_route_table.terraform-public-route-table-master.id
  destination_cidr_block    = aws_vpc.terraform-default-vpc-slave.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.default-peering-slave.id    
}
*/
resource "aws_route_table" "terraform-private-route-table-slave" {
  vpc_id = aws_vpc.terraform-default-vpc-slave.id

  # Route all traffic through VPC peering (simulating on-premise to AWS connection)
  # Note: This won't provide internet access due to VPC peering non-transitive nature
  # This simulates a Direct Connect or VPN connection from on-premise to AWS
  route {
    cidr_block = "0.0.0.0/0"
    vpc_peering_connection_id = aws_vpc_peering_connection.default-peering-slave.id
  }
  
  tags = {
    Name = "terraform-private-route-table-slave-onpremise"
  }
}

# How to create master internet gateway
resource "aws_internet_gateway" "terraform-default-igw-master" {
  vpc_id = aws_vpc.terraform-default-vpc-master.id

  tags = {
    Name = "terraform-igw-master"
  }
}

# How to create private internet gateway
resource "aws_internet_gateway" "terraform-default-igw-slave" {
  vpc_id = aws_vpc.terraform-default-vpc-slave.id

  tags = {
    Name = "terraform-igw-slave"
  }
}


# How to associate route table with specific subnet
resource "aws_route_table_association" "public-subnet-rt-association-master" {
  subnet_id      = aws_subnet.terraform-public-subnet-master.id
  route_table_id = aws_route_table.terraform-public-route-table-master.id
}

resource "aws_route_table_association" "private-subnet-rt-association-master" {
  subnet_id      = aws_subnet.terraform-private-subnet-master.id
  route_table_id = aws_route_table.terraform-private-route-table-master.id
}

# How to associate route table with specific subnet
resource "aws_route_table_association" "public-subnet-rt-association-slave" {
  subnet_id      = aws_subnet.terraform-public-subnet-slave.id
  route_table_id = aws_route_table.terraform-public-route-table-slave.id
}

resource "aws_route_table_association" "private-subnet-rt-association-slave" {
  subnet_id      = aws_subnet.terraform-private-subnet-slave.id
  route_table_id = aws_route_table.terraform-private-route-table-slave.id
}

# Create public facing security group
resource "aws_security_group" "terraform-public-facing-db-sg-master" {
  vpc_id = aws_vpc.terraform-default-vpc-master.id
  name   = "public-facing-db-sg-master"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.terraform-public-subnet-master.cidr_block]
    description = "Allow RDP from master public subnet"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [aws_subnet.terraform-public-subnet-master.cidr_block]
    description = "Allow ICMP from master public subnet"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.terraform-default-vpc-slave.cidr_block]
    description = "Allow HTTPS from slave VPC for SSM"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-public-facing-db-sg-master"
  }
}

# Create private security group
resource "aws_security_group" "terraform-db-sg-master" {
  vpc_id = aws_vpc.terraform-default-vpc-master.id
  name   = "private-facing-db-sg-master"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    # Allow traffic from private subnets
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-private-facing-db-sg-master"
  }
}

# Create public facing security group
resource "aws_security_group" "terraform-public-facing-db-sg-slave" {
  vpc_id = aws_vpc.terraform-default-vpc-slave.id
  name   = "public-facing-db-sg-slave"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    # Allow traffic from public subnet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-public-facing-db-sg-slave"
  }
}

# Create private security group for slave - allow RDP from master VPC
resource "aws_security_group" "terraform-db-sg-slave" {
  vpc_id = aws_vpc.terraform-default-vpc-slave.id
  name   = "private-facing-db-sg-slave"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.terraform-default-vpc-master.cidr_block]
    description = "Allow RDP from master VPC"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [aws_vpc.terraform-default-vpc-master.cidr_block]
    description = "Allow ICMP from master VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-private-facing-db-sg-slave"
  }
}

# Comment this out to cut cost and focus on igw only
/*
resource "aws_eip" "terraform-nat-eip" {
  vpc = true
   tags = {
      Name = "terraform-nat-eip"
      }
}

resource "aws_nat_gateway" "terraform-ngw" {
  allocation_id = aws_eip.terraform-nat-eip.id
  subnet_id     = aws_subnet.terraform-public-subnet.id
  tags = {
      Name = "terraform-nat-gateway"
      }
}
*/

# IAM Role for SSM
resource "aws_iam_role" "ssm_role" {
  name = "SSMRoleForEC2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "SSM-Role-For-EC2"
  }
}

# Attach AWS managed policy for SSM
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Create instance profile
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "SSMInstanceProfile"
  role = aws_iam_role.ssm_role.name

  tags = {
    Name = "SSM-Instance-Profile"
  }
}
