variable "region" {
  type = string
}

variable "event_name" {
  type = string
  validation {
    condition     = can(regex("^[-a-zA-Z0-9_]+$", var.event_name))
    error_message = "Event name must only contain alphanumeric characters, dashes, and underscores."
  }
}

variable "leaderboard_http_image" {
  type = string
}

variable "leaderboard_record_image" {
  type = string
}

variable "vault_address" {
  type = string
}

variable "vault_token" {
  type      = string
  sensitive = true
}

variable "vault_namespace" {
  type = string
}