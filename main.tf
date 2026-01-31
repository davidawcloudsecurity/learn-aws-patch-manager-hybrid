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
resource "aws_instance" "dev-instance-linux2-master" {
  ami                         = "ami-018ba43095ff50d08"
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
    #volume_size           = 50
    volume_type           = "gp2"
    delete_on_termination = true
  }
  user_data = <<EOF
#!/bin/bash
# Define the path to the sshd_config file
sshd_config="/etc/ssh/sshd_config"

# Define the string to be replaced
old_string="PasswordAuthentication no"
new_string="PasswordAuthentication yes"

# Check if the file exists
if [ -e "$sshd_config" ]; then
    # Use sed to replace the old string with the new string
    sudo sed -i "s/$old_string/$new_string/" "$sshd_config"

    # Check if the sed command was successful
    if [ $? -eq 0 ]; then
        echo "String replaced successfully."
        # Restart the SSH service to apply the changes
        sudo service ssh restart
    else
        echo "Error replacing string in $sshd_config."
    fi
else
    echo "File $sshd_config not found."
fi

echo "Letmein2021" | passwd --stdin ec2-user
systemctl restart sshd

# Install Docker
yum update -y
yum install docker -y
systemctl start docker

# Pull and run Ambience from Docker
yum install git -y
cd /home/ec2-user
git clone https://github.com/ambience-cloud/elixir-ambience.git
curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
cd elixir-ambience

# sed -i 's/"//g' ".env"
# sed -i 's/mongourl=mongodb:\/\/mongo:27017/mongourl=mongodb:\/\/10.2.4.199:27017/g' ".env"
# sed -i 's/externalhost=localhost/externalhost=testssl123.click/g' ".env"
# sed -i 's/externalport=1740/externalport=443/g' ".env"
# sed -i 's/externalprotocol=http/externalprotocol=https/g' ".env"
cat << EOF3 > ./docker-compose.yaml
version: "3"
services:
  elixir-ambience:
    container_name: elixir-ambience
    image: elixirtech/elixir-ambience
    environment:
       #mongodb running in host for Windows and OSx
       #mongodb part of docker compose
       - mongourl=$\{mongourl\}
       - externalhost=$\{externalhost\}
       - externalport=$\{externalport\}
       - externalprotocol=$\{externalprotocol\}
    ports:
       - 1740:1740
#volumes:
#  elixirmongodbdata:
EOF3
sed -i 's/\\//g' "./docker-compose.yaml"
# docker-compose up
EOF

  tags = {
    Name = "dev-instance-linux2-terraform-master"
  }
}

# Create instance in one of the subnet
resource "aws_instance" "dev-instance-linux2-slave" {
  ami                         = "ami-018ba43095ff50d08"
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
    #volume_size           = 50
    volume_type           = "gp2"
    delete_on_termination = true
  }
  user_data = <<EOF
#!/bin/bash
yum update -y
yum install docker -y
systemctl start docker
usermod -a -G docker ec2-user
newgrp docker
systemctl start docker
docker run --network host -d mongo

# Define the path to the sshd_config file
sshd_config="/etc/ssh/sshd_config"

# Define the string to be replaced
old_string="PasswordAuthentication no"
new_string="PasswordAuthentication yes"

# Check if the file exists
if [ -e "$sshd_config" ]; then
    # Use sed to replace the old string with the new string
    sudo sed -i "s/$old_string/$new_string/" "$sshd_config"

    # Check if the sed command was successful
    if [ $? -eq 0 ]; then
        echo "String replaced successfully."
        # Restart the SSH service to apply the changes
        sudo service ssh restart
    else
        echo "Error replacing string in $sshd_config."
    fi
else
    echo "File $sshd_config not found."
fi
echo "Letmein2021" | passwd --stdin ec2-user
systemctl restart sshd
EOF

  tags = {
    Name = "dev-instance-linux2-terraform-slave"
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
