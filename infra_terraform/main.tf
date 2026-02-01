terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = "us-east-1"
}

# S3 Bucket
resource "aws_s3_bucket" "patch_manager_bucket" {
  bucket = "learn-aws-patch-manager-hybrid"
}

# S3 Bucket Server Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "patch_manager_encryption" {
  bucket = aws_s3_bucket.patch_manager_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "patch_manager_policy" {
  bucket = aws_s3_bucket.patch_manager_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = aws_iam_role.ssm_role.arn }
      Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.patch_manager_bucket.arn,
        "${aws_s3_bucket.patch_manager_bucket.arn}/*"
      ]
    }]
  })
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "patch_manager_pab" {
  bucket = aws_s3_bucket.patch_manager_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Set timezone
Set-TimeZone -Id "Singapore Standard Time"

Write-Host "On-premise simulation configuration completed."
Write-Host "This instance has no direct internet access - use SSM hybrid activation for management"
Stop-Service AmazonSSMAgent -Force
Remove-Service AmazonSSMAgent
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

# Get TGW default route table ID
data "aws_ec2_transit_gateway_route_table" "default" {
  filter {
    name   = "transit-gateway-id"
    values = [aws_ec2_transit_gateway.main.id]
  }
  filter {
    name   = "default-association-route-table"
    values = ["true"]
  }
  
  depends_on = [aws_ec2_transit_gateway.main]
}

# Route internet traffic (0.0.0.0/0) from on-premise to AWS VPC NAT Gateway
resource "aws_ec2_transit_gateway_route" "onpremise_to_internet" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.aws_vpc.id
  transit_gateway_route_table_id = data.aws_ec2_transit_gateway_route_table.default.id
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
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.terraform-ngw-aws.id
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
    Name = "terraform-private-route-table-aws"
  }
}

# How to create custom route table
resource "aws_route_table" "terraform-public-route-table-onpremise" {
  vpc_id = aws_vpc.terraform-default-vpc-onpremise.id
  
  # Default route to internet via TGW -> AWS VPC NAT Gateway
  route {
    cidr_block         = "0.0.0.0/0"
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

  # Default route to internet via TGW -> AWS VPC NAT Gateway
  # This covers both internet access and AWS VPC communication
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

# NAT Gateway for AWS VPC - shared with on-premise via TGW
resource "aws_eip" "terraform-nat-eip" {
  domain = "vpc"
  tags = {
    Name = "terraform-nat-eip-aws"
  }
}

resource "aws_nat_gateway" "terraform-ngw-aws" {
  allocation_id = aws_eip.terraform-nat-eip.id
  subnet_id     = aws_subnet.terraform-public-subnet-aws.id
  tags = {
    Name = "terraform-nat-gateway-aws"
  }
  
  depends_on = [aws_internet_gateway.terraform-default-igw-aws]
}

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

# Outputs
output "nat_gateway_public_ip" {
  description = "Public IP of NAT Gateway used by on-premise VPC"
  value       = aws_eip.terraform-nat-eip.public_ip
}

output "aws_instance_public_ip" {
  description = "Public IP of AWS Windows instance"
  value       = aws_instance.dev-instance-windows-aws.public_ip
}

output "aws_instance_id" {
  description = "Instance ID of AWS Windows instance"
  value       = aws_instance.dev-instance-windows-aws.id
}

output "onpremise_instance_private_ip" {
  description = "Private IP of on-premise Windows instance"
  value       = aws_instance.dev-instance-windows-onpremise.private_ip
}

output "onpremise_instance_id" {
  description = "Instance ID of on-premise Windows instance"
  value       = aws_instance.dev-instance-windows-onpremise.id
}

output "transit_gateway_id" {
  description = "Transit Gateway ID"
  value       = aws_ec2_transit_gateway.main.id
}

# Output the bucket name and ARN
output "bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.patch_manager_bucket.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.patch_manager_bucket.arn
}

output "bucket_domain_name" {
  description = "Domain name of the S3 bucket"
  value       = aws_s3_bucket.patch_manager_bucket.bucket_domain_name
}
