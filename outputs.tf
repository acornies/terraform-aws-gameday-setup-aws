output "aws_participant_sqs_arn" {
  value = aws_sqs_queue.participant.arn
}

output "aws_leaderboard_sqs_arn" {
  value = aws_sqs_queue.leaderboard.arn
}

output "aws_participant_sqs_url" {
  value = aws_sqs_queue.participant.url
}

output "aws_leaderboard_sqs_url" {
  value = aws_sqs_queue.leaderboard.url
}

# output "aws_leaderboard_http_ecr_repo" {
#   value = aws_ecr_repository.leaderboard_http.repository_url
# }

# output "aws_leaderboard_rec_ecr_repo" {
#   value = aws_ecr_repository.leaderboard_rec.repository_url
# }

output "aws_leaderboard_http_function_url" {
  value = aws_lambda_function_url.leaderboard_http.function_url
}

output "aws_leaderboard_rds_instance_password" {
  value     = random_password.password.result
  sensitive = true
}

output "aws_leaderboard_rds_instance_address" {
  value = aws_db_instance.leaderboard.address
}

output "aws_leaderboard_rds_instance_endpoint" {
  value = aws_db_instance.leaderboard.endpoint
}

output "aws_leaderboard_html_endpoint" {
  value = aws_s3_bucket_website_configuration.leaderboard.website_endpoint
}