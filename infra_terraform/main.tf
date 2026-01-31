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
resource "aws_instance" "dev-instance-windows-aws" {
  ami                         = "ami-0f73246b6299f4858"
  instance_type               = "t3.large"
  availability_zone           = "us-east-1a"
  tenancy                     = "default"
  subnet_id                   = aws_subnet.terraform-public-subnet-aws.id # Public Subnet A
  ebs_optimized               = false
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
  vpc_security_group_ids = [
    aws_security_group.terraform-public-facing-db-sg-aws.id # public-facing-security-group
  ]
  source_dest_check           = true
  disable_api_termination     = false
  root_block_device {
    volume_type           = "gp2"
    delete_on_termination = true
  }
  user_data = <<EOF
<powershell>
# Basic Windows configuration
Write-Host "Configuring Windows instance..."
# Create local user ec2-user with password
$Password = ConvertTo-SecureString "Letmein2021" -AsPlainText -Force
New-LocalUser "ec2-user" -Password $Password -FullName "EC2 User" -Description "Local user for on-premise simulation"
Add-LocalGroupMember -Group "Administrators" -Member "ec2-user"
# Add ec2-user to Remote Management Users group
Add-LocalGroupMember -Group "Remote Management Users" -Member "ec2-user"

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Set timezone
Set-TimeZone -Id "Singapore Standard Time"

Write-Host "Windows configuration completed."
</powershell>
EOF

  tags = {
    Name = "dev-instance-windows-terraform-aws"
  }
}

# Create instance in private subnet to simulate on-premise server
resource "aws_instance" "dev-instance-windows-onpremise" {
  ami                         = "ami-0f73246b6299f4858"
  instance_type               = "t3.large"
  availability_zone           = "us-east-1b"
  tenancy                     = "default"
  subnet_id                   = aws_subnet.terraform-private-subnet-onpremise.id # Private Subnet - simulating on-premise
  ebs_optimized               = false
  associate_public_ip_address = false # No public IP - simulating on-premise
  vpc_security_group_ids = [
    aws_security_group.terraform-db-sg-onpremise.id # private-facing-security-group
  ]
  source_dest_check           = true
  disable_api_termination     = false
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
Add-LocalGroupMember -Group "Remote Management Users" -Member "ec2-user"

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Set timezone
Set-TimeZone -Id "Singapore Standard Time"

Write-Host "On-premise simulation configuration completed."
Write-Host "User: ec2-user | Password: Letmein2021"
Write-Host "This instance has no direct internet access - use SSM hybrid activation for management"
</powershell>
EOF

  tags = {
    Name = "dev-instance-windows-terraform-onpremise"
  }
}

# Transit Gateway
resource "aws_ec2_transit_gateway" "main" {
  description                     = "Transit Gateway for AWS and On-Premise VPC connectivity"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"
  dns_support                     = "enable"
  
  tags = {
    Name = "tgw-aws-onpremise"
  }
}

# TGW Attachment for AWS VPC
resource "aws_ec2_transit_gateway_vpc_attachment" "aws_vpc" {
  subnet_ids         = [aws_subnet.terraform-private-subnet-aws.id]
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.terraform-default-vpc-aws.id
  dns_support        = "enable"
  
  tags = {
    Name = "tgw-attachment-aws-vpc"
  }
}

# TGW Attachment for On-Premise VPC
resource "aws_ec2_transit_gateway_vpc_attachment" "onpremise_vpc" {
  subnet_ids         = [aws_subnet.terraform-private-subnet-onpremise.id]
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.terraform-default-vpc-onpremise.id
  dns_support        = "enable"
  
  tags = {
    Name = "tgw-attachment-onpremise-vpc"
  }
}

resource "aws_vpc" "terraform-default-vpc-aws" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "learn-terraform-vpc-aws"
  }
}

resource "aws_vpc" "terraform-default-vpc-onpremise" {
  cidr_block           = "172.16.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "learn-terraform-vpc-onpremise"
  }
}

# How to create public / private subnet
resource "aws_subnet" "terraform-public-subnet-aws" {
  vpc_id            = aws_vpc.terraform-default-vpc-aws.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "terraform-public-subnet-aws-A"
  }
}

resource "aws_subnet" "terraform-private-subnet-aws" {
  vpc_id            = aws_vpc.terraform-default-vpc-aws.id
  cidr_block        = "10.10.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "terraform-private-subnet-aws-A"
  }
}

# How to create public / private subnet
resource "aws_subnet" "terraform-public-subnet-onpremise" {
  vpc_id            = aws_vpc.terraform-default-vpc-onpremise.id
  cidr_block        = "172.16.1.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "terraform-public-subnet-onpremise-B"
  }
}

resource "aws_subnet" "terraform-private-subnet-onpremise" {
  vpc_id            = aws_vpc.terraform-default-vpc-onpremise.id
  cidr_block        = "172.16.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "terraform-private-subnet-onpremise-B"
  }
}

# How to create custom route table
resource "aws_route_table" "terraform-public-route-table-aws" {
  vpc_id = aws_vpc.terraform-default-vpc-aws.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.terraform-default-igw-aws.id
  }
  
  route {
    cidr_block         = aws_vpc.terraform-default-vpc-onpremise.cidr_block
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }
  
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.aws_vpc,
    aws_ec2_transit_gateway_vpc_attachment.onpremise_vpc
  ]
    
  tags = {
    Name = "terraform-public-route-table-aws"
  }
}

resource "aws_route_table" "terraform-private-route-table-aws" {
  vpc_id = aws_vpc.terraform-default-vpc-aws.id

  route {
    cidr_block         = aws_vpc.terraform-default-vpc-onpremise.cidr_block
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }
  
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.aws_vpc,
    aws_ec2_transit_gateway_vpc_attachment.onpremise_vpc
  ]

  tags = {
    Name = "terraform-private-route-table-aws"
  }
}

# How to create custom route table
resource "aws_route_table" "terraform-public-route-table-onpremise" {
  vpc_id = aws_vpc.terraform-default-vpc-onpremise.id
  
  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }
  
  route {
    cidr_block         = aws_vpc.terraform-default-vpc-aws.cidr_block
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }
  
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.aws_vpc,
    aws_ec2_transit_gateway_vpc_attachment.onpremise_vpc
  ]

  tags = {
    Name = "terraform-public-route-table-onpremise"
  }
}

resource "aws_route_table" "terraform-private-route-table-onpremise" {
  vpc_id = aws_vpc.terraform-default-vpc-onpremise.id

  # Route all traffic through Transit Gateway (simulating on-premise to AWS connection)
  # This simulates a Direct Connect or VPN connection from on-premise to AWS
  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }
  
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.aws_vpc,
    aws_ec2_transit_gateway_vpc_attachment.onpremise_vpc
  ]
  
  tags = {
    Name = "terraform-private-route-table-onpremise"
  }
}

# How to create aws internet gateway
resource "aws_internet_gateway" "terraform-default-igw-aws" {
  vpc_id = aws_vpc.terraform-default-vpc-aws.id

  tags = {
    Name = "terraform-igw-aws"
  }
}

# How to create private internet gateway
resource "aws_internet_gateway" "terraform-default-igw-onpremise" {
  vpc_id = aws_vpc.terraform-default-vpc-onpremise.id

  tags = {
    Name = "terraform-igw-onpremise"
  }
}


# How to associate route table with specific subnet
resource "aws_route_table_association" "public-subnet-rt-association-aws" {
  subnet_id      = aws_subnet.terraform-public-subnet-aws.id
  route_table_id = aws_route_table.terraform-public-route-table-aws.id
}

resource "aws_route_table_association" "private-subnet-rt-association-aws" {
  subnet_id      = aws_subnet.terraform-private-subnet-aws.id
  route_table_id = aws_route_table.terraform-private-route-table-aws.id
}

# How to associate route table with specific subnet
resource "aws_route_table_association" "public-subnet-rt-association-onpremise" {
  subnet_id      = aws_subnet.terraform-public-subnet-onpremise.id
  route_table_id = aws_route_table.terraform-public-route-table-onpremise.id
}

resource "aws_route_table_association" "private-subnet-rt-association-onpremise" {
  subnet_id      = aws_subnet.terraform-private-subnet-onpremise.id
  route_table_id = aws_route_table.terraform-private-route-table-onpremise.id
}

# Create public facing security group
resource "aws_security_group" "terraform-public-facing-db-sg-aws" {
  vpc_id = aws_vpc.terraform-default-vpc-aws.id
  name   = "public-facing-db-sg-aws"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.terraform-public-subnet-aws.cidr_block]
    description = "Allow RDP from aws public subnet"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [aws_subnet.terraform-public-subnet-aws.cidr_block]
    description = "Allow ICMP from aws public subnet"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.terraform-default-vpc-onpremise.cidr_block]
    description = "Allow HTTPS from onpremise VPC for SSM"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-public-facing-db-sg-aws"
  }
}

# Create private security group
resource "aws_security_group" "terraform-db-sg-aws" {
  vpc_id = aws_vpc.terraform-default-vpc-aws.id
  name   = "private-facing-db-sg-aws"

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
    Name = "terraform-private-facing-db-sg-aws"
  }
}

# Create public facing security group
resource "aws_security_group" "terraform-public-facing-db-sg-onpremise" {
  vpc_id = aws_vpc.terraform-default-vpc-onpremise.id
  name   = "public-facing-db-sg-onpremise"

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
    Name = "terraform-public-facing-db-sg-onpremise"
  }
}

# Create private security group for onpremise - allow all traffic from aws VPC
resource "aws_security_group" "terraform-db-sg-onpremise" {
  vpc_id = aws_vpc.terraform-default-vpc-onpremise.id
  name   = "private-facing-db-sg-onpremise"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.terraform-default-vpc-aws.cidr_block]
    description = "Allow all traffic from aws VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "terraform-private-facing-db-sg-onpremise"
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

# S3 Gateway Endpoint for On-Premise VPC (free!)
resource "aws_vpc_endpoint" "s3_onpremise" {
  vpc_id            = aws_vpc.terraform-default-vpc-onpremise.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [
    aws_route_table.terraform-private-route-table-onpremise.id,
    aws_route_table.terraform-public-route-table-onpremise.id
  ]

  tags = {
    Name = "s3-endpoint-onpremise"
  }
}
