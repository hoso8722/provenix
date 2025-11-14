variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "provenix"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "node_group_desired_capacity" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 2
}

variable "node_group_max_capacity" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 4
}

variable "node_group_min_capacity" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 1
}

variable "node_instance_types" {
  description = "EC2 instance types for worker nodes"
  type        = list(string)
  default     = ["m5.large"]
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage (GB)"
  type        = number
  default     = 20
}

variable "db_password" {
  description = "RDS password"
  type        = string
  sensitive   = true
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "provenix"
    ManagedBy   = "terraform"
  }
}