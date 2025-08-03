# custodian-setup\modules\custodian-iam\custodian-iam.tf

# ================================
# Variables
# ================================

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "account_id" {
  description = "AWS account ID"
  type        = string
}

variable "lambda_role_name" {
  description = "Name of the Custodian Lambda IAM role"
  type        = string
}

variable "mailer_role_name" {
  description = "Name of the c7n-mailer IAM role"
  type        = string
}

variable "sqs_queue_arn" {
  description = "ARN of the SQS queue for notifications"
  type        = string
}

# ================================
# IAM Roles
# ================================

# Custodian Lambda 실행용 IAM Role
resource "aws_iam_role" "custodian_lambda_role" {
  name = var.lambda_role_name
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = [
          "lambda.amazonaws.com",
          "events.amazonaws.com",
          "cloudtrail.amazonaws.com"
        ] }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# Mailer 실행용 IAM Role
resource "aws_iam_role" "c7n_mailer_role" {
  name = var.mailer_role_name
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# ================================
# IAM Role Policy Attachments (Managed Policies)
# ================================

# CloudWatch 로그 기록용 기본 정책 (Lambda용 AWS 관리형)
resource "aws_iam_role_policy_attachment" "poweruser_attach" {
  role       = aws_iam_role.custodian_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# PowerUserAccess만으로 권한이 모자랄 시 주석을 풀고 활성화하세요.
#resource "aws_iam_role_policy_attachment" "admin_policy" {
#  role       = aws_iam_role.custodian_lambda_role.name
#  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
#}


resource "aws_iam_role_policy_attachment" "mailer_basic_execution" {
  role       = aws_iam_role.c7n_mailer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ================================
# IAM Inline Policies - Custodian Lambda
# ================================

# 1. 리소스 조회 권한
resource "aws_iam_role_policy" "custodian_iam_policy" {
  name = "${var.lambda_role_name}-iam-policy"
  role = aws_iam_role.custodian_lambda_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:ListAccountAliases"
      ]
      Resource = "*"
    }]
  })
}

# ================================
# IAM Inline Policies - Mailer
# ================================

# 2. SES 권한 (Slack 대체 이메일 알림용)
resource "aws_iam_role_policy" "mailer_ses_policy" {
  name = "${var.mailer_role_name}-ses-policy"
  role = aws_iam_role.c7n_mailer_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ses:SendEmail",
        "ses:SendRawEmail",
        "ses:GetSendQuota",
        "ses:GetSendStatistics"
      ]
      Resource = "*"
    }]
  })
}

# 3. CloudWatch 로그 기록 권한
resource "aws_iam_role_policy" "mailer_logs_policy" {
  name = "${var.mailer_role_name}-logs-policy"
  role = aws_iam_role.c7n_mailer_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/c7n-mailer-*"
    }]
  })
}

# 4. SQS 권한 (알림 수신)
resource "aws_iam_role_policy" "mailer_sqs_access" {
  name = "${var.mailer_role_name}-sqs-access"
  role = aws_iam_role.c7n_mailer_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ]
      Resource = var.sqs_queue_arn
    }]
  })
}

# ================================
# Outputs
# ================================

output "custodian_lambda_role_arn" {
  description = "ARN of the Custodian Lambda IAM role"
  value       = aws_iam_role.custodian_lambda_role.arn
}

output "c7n_mailer_role_arn" {
  description = "ARN of the c7n-mailer IAM role"
  value       = aws_iam_role.c7n_mailer_role.arn
}
