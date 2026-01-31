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
  instance_type               = "t2.micro"
  key_name                    = "ambience-developer-cloud"
  availability_zone           = "us-east-1a"
  tenancy                     = "default"
  subnet_id                   = aws_subnet.terraform-public-subnet-master.id # Public Subnet A
  ebs_optimized               = false
  associate_public_ip_address = true
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

# Create instance in one of the subnet
resource "aws_instance" "dev-instance-windows-slave" {
  ami                         = "ami-0f73246b6299f4858"
  instance_type               = "t2.micro"
  key_name                    = "ambience-developer-cloud"
  availability_zone           = "us-east-1b"
  tenancy                     = "default"
  subnet_id                   = aws_subnet.terraform-public-subnet-slave.id # Public Subnet A
  ebs_optimized               = false
  associate_public_ip_address = true
  vpc_security_group_ids = [
    aws_security_group.terraform-public-facing-db-sg-slave.id # public-facing-security-group
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
    Name = "dev-instance-windows-terraform-slave"
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
  cidr_block           = "10.2.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "learn-terraform-vpc-slave"
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
  cidr_block        = "10.2.1.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "terraform-public-subnet-slave-B"
  }
}

resource "aws_subnet" "terraform-private-subnet-slave" {
  vpc_id            = aws_vpc.terraform-default-vpc-slave.id
  cidr_block        = "10.2.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "terrform-private-subnet-slave-B"
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
    gateway_id = aws_internet_gateway.terraform-default-igw-slave.id
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

  # Comment this out to cut cost and focus on igw only
/*  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.terraform-ngw.id
  }
*/  
  tags = {
    Name = "terraform-private-route-table-slave"
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

# Create private security group
resource "aws_security_group" "terraform-db-sg-slave" {
  vpc_id = aws_vpc.terraform-default-vpc-slave.id
  name   = "private-facing-db-sg-slave"

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
