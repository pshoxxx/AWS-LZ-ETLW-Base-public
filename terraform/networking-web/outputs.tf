output "web_alb_dns_name" {
  description = "DNS name of the internet-facing ALB for the web spoke. Empty until web_endpoint_service_name is set."
  value       = length(aws_lb.web) > 0 ? aws_lb.web[0].dns_name : ""
}
