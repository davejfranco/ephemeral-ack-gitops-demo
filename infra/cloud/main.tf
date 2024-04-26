/* terraform */
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.47.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
}

/* datasource */

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "current" {}

/* network settings */
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "${local.prefix}-vpc"
  cidr = local.network.cidr

  azs             = local.network.az
  private_subnets = [for i in range(length(local.network.az)) : cidrsubnet(local.network.cidr, 8, i)]
  public_subnets  = [for i in range(length(local.network.az)) : cidrsubnet(local.network.cidr, 8, i + 3)]

  # single NAT per network
  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = true

  tags = local.default_tags
}


resource "aws_security_group" "rds" {
  name        = "${local.prefix}-rds-sg"
  description = "Allow DB inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = []
  }

  tags = merge(
    { Name : "${local.prefix}-rds-sg" },
    local.default_tags
  )
}

/* RDS */
module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier = "${local.prefix}-db"

  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t4g.micro"
  allocated_storage = 5

  db_name  = "demodb"
  username = "demouser"
  port     = "3306"

  iam_database_authentication_enabled = false

  vpc_security_group_ids = [aws_security_group.rds.id]

  maintenance_window = "Mon:00:00-Mon:03:00"
  backup_window      = "03:00-06:00"

  # DB subnet group
  create_db_subnet_group = true
  subnet_ids             = module.vpc.private_subnets

  # DB parameter group
  family = "mysql8.0"

  # DB option group
  major_engine_version = "8.0"

  # Database Deletion Protection
  deletion_protection = false

  tags = local.default_tags
}

/* EKS Cluster */
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "${local.prefix}-eks"
  cluster_version = "1.29"

  cluster_endpoint_public_access = true

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets


  eks_managed_node_groups = {
    demo = {
      min_size     = 1
      max_size     = 2
      desired_size = 1

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
    }
  }

  # Cluster access entry
  # To add the current caller identity as an administrator
  enable_cluster_creator_admin_permissions = true


  tags = local.default_tags
}

/* IAM */
# External Secrets
data "aws_iam_policy_document" "external_secrets_trust_policy" {
  statement {
    sid     = "externalsecret"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}"]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:external-secrets:external-secrets"]
      variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub"
    }
  }
}

resource "aws_iam_role" "external_secrets" {
  name               = "${local.prefix}-external-secrets-role"
  assume_role_policy = data.aws_iam_policy_document.external_secrets_trust_policy.json
}

data "aws_iam_policy_document" "external_secrets_access" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds"
    ]
    resources = [
      "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:*"
    ]
  }
}

resource "aws_iam_policy" "external_secrets" {
  name   = "${local.prefix}-es-access"
  policy = data.aws_iam_policy_document.external_secrets_access.json
}

resource "aws_iam_policy_attachment" "external_secrets" {
  name       = "${local.prefix}-es-attachment"
  roles      = [aws_iam_role.external_secrets.name]
  policy_arn = aws_iam_policy.external_secrets.arn
}

# External DNS
data "aws_iam_policy_document" "external_dns_trust_policy" {
  statement {
    sid     = "externaldns"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}"]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:external-dns:external-dns"]
      variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub"
    }
  }
}

resource "aws_iam_role" "external_dns" {
  name               = "${local.prefix}-external-dns-role"
  assume_role_policy = data.aws_iam_policy_document.external_dns_trust_policy.json
}

data "aws_iam_policy_document" "external_dns_access" {
  statement {
    effect = "Allow"
    actions = [
      "route53:ChangeResourceRecordSets"
    ]
    resources = [
      "arn:aws:route53:::hostedzone/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:ListTagsForResource"
    ]
    resources = ["*"]
  }

}

resource "aws_iam_policy" "external_dns" {
  name   = "${local.prefix}-edns-access"
  policy = data.aws_iam_policy_document.external_dns_access.json
}

resource "aws_iam_policy_attachment" "external_dns" {
  name       = "${local.prefix}-edns-attachment"
  roles      = [aws_iam_role.external_dns.name]
  policy_arn = aws_iam_policy.external_dns.arn
}

# ACK
## IAM
data "aws_iam_policy_document" "ack_iam_trust_policy" {
  statement {
    sid     = "externaldns"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}"]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:ack-system:iam-controller-sa"]
      variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub"
    }
  }
}

resource "aws_iam_role" "ack_iam" {
  name               = "${local.prefix}-ack-iam-role"
  assume_role_policy = data.aws_iam_policy_document.ack_iam_trust_policy.json
}

data "aws_iam_policy_document" "ack_iam_access" {
  statement {
    effect = "Allow"
    actions = [
      "iam:GetGroup",
      "iam:CreateGroup",
      "iam:DeleteGroup",
      "iam:UpdateGroup",
      "iam:GetRole",
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:UpdateRole",
      "iam:PutRolePermissionsBoundary",
      "iam:PutUserPermissionsBoundary",
      "iam:GetUser",
      "iam:CreateUser",
      "iam:DeleteUser",
      "iam:UpdateUser",
      "iam:GetPolicy",
      "iam:CreatePolicy",
      "iam:DeletePolicy",
      "iam:GetPolicyVersion",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
      "iam:ListPolicyVersions",
      "iam:ListPolicyTags",
      "iam:ListAttachedGroupPolicies",
      "iam:GetGroupPolicy",
      "iam:PutGroupPolicy",
      "iam:AttachGroupPolicy",
      "iam:DetachGroupPolicy",
      "iam:DeleteGroupPolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:PutRolePolicy",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies",
      "iam:GetUserPolicy",
      "iam:PutUserPolicy",
      "iam:AttachUserPolicy",
      "iam:DetachUserPolicy",
      "iam:DeleteUserPolicy",
      "iam:ListRoleTags",
      "iam:ListUserTags",
      "iam:TagPolicy",
      "iam:UntagPolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:TagUser",
      "iam:UntagUser",
      "iam:RemoveClientIDFromOpenIDConnectProvider",
      "iam:ListOpenIDConnectProviderTags",
      "iam:UpdateOpenIDConnectProviderThumbprint",
      "iam:UntagOpenIDConnectProvider",
      "iam:AddClientIDToOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:GetOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider",
      "iam:CreateOpenIDConnectProvider",
      "iam:UpdateAssumeRolePolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ack_iam" {
  name   = "${local.prefix}-ack-iam-access"
  policy = data.aws_iam_policy_document.ack_iam_access.json
}

resource "aws_iam_policy_attachment" "ack_iam" {
  name       = "${local.prefix}-ack-iam-attachment"
  roles      = [aws_iam_role.ack_iam.name]
  policy_arn = aws_iam_policy.ack_iam.arn
}
## S3
data "aws_iam_policy_document" "ack_s3_trust_policy" {
  statement {
    sid     = "externaldns"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}"]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:ack-system:s3-controller-sa"]
      variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub"
    }
  }
}

resource "aws_iam_role" "ack_s3" {
  name               = "${local.prefix}-ack-s3-role"
  assume_role_policy = data.aws_iam_policy_document.ack_s3_trust_policy.json
}

data "aws_iam_policy_document" "ack_s3_access" {
  statement {
    effect = "Allow"
    actions = [
      "s3:*",
      "s3-object-lambda:*"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "S3ReplicationPassRole"
    effect = "Allow"
    actions = [
      "iam:PassRole"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "ack_s3" {
  name   = "${local.prefix}-ack-s3-access"
  policy = data.aws_iam_policy_document.ack_s3_access.json
}

resource "aws_iam_policy_attachment" "ack_s3" {
  name       = "${local.prefix}-ack-s3-attachment"
  roles      = [aws_iam_role.ack_s3.name]
  policy_arn = aws_iam_policy.ack_s3.arn
}

resource "aws_iam_policy_attachment" "ack_s3_full" {
  name       = "${local.prefix}-ack-s3-full-attachment"
  roles      = [aws_iam_role.ack_s3.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

## RDS 
data "aws_iam_policy_document" "ack_rds_trust_policy" {
  statement {
    sid     = "externaldns"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}"]
      type        = "Federated"
    }

    condition {
      test     = "StringEquals"
      values   = ["system:serviceaccount:ack-system:rds-controller-sa"]
      variable = "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub"
    }
  }
}

resource "aws_iam_role" "ack_rds" {
  name               = "${local.prefix}-ack-rds-role"
  assume_role_policy = data.aws_iam_policy_document.ack_rds_trust_policy.json
}

resource "aws_iam_policy_attachment" "ack_rds_full" {
  name       = "${local.prefix}-ack-rds-full-attachment"
  roles      = [aws_iam_role.ack_rds.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

