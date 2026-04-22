# ==================================================================================
# GCP Service Account and IAM Configuration for Asset Counter
# ==================================================================================
#
# This Terraform configuration creates:
# 1. A service account for the asset counter
# 2. IAM role bindings with Cloud Asset Viewer permissions
# 3. Service account key (optional)
#
# Usage:
#   terraform init
#   terraform plan -var="project_id=your-project-id"
#   terraform apply -var="project_id=your-project-id"
#
# ==================================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "project_id" {
  description = "GCP Project ID where the service account will be created"
  type        = string
}

variable "service_account_name" {
  description = "Name of the service account"
  type        = string
  default     = "asset-counter"
}

variable "service_account_display_name" {
  description = "Display name of the service account"
  type        = string
  default     = "Asset Counter Service Account"
}

variable "create_key" {
  description = "Whether to create and download a service account key"
  type        = bool
  default     = true
}

variable "additional_project_ids" {
  description = "Additional project IDs to grant access to (for multi-project scanning)"
  type        = list(string)
  default     = []
}

variable "organization_id" {
  description = "Organization ID for organization-level access (optional)"
  type        = string
  default     = ""
}

# Provider configuration
provider "google" {
  project = var.project_id
}

# Create service account
resource "google_service_account" "asset_counter" {
  account_id   = var.service_account_name
  display_name = var.service_account_display_name
  description  = "Service account for cloud asset inventory and counting"
  project      = var.project_id
}

# Grant Cloud Asset Viewer role at project level
resource "google_project_iam_member" "asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = "serviceAccount:${google_service_account.asset_counter.email}"
}

# Grant Browser role (for listing resources)
resource "google_project_iam_member" "browser" {
  project = var.project_id
  role    = "roles/browser"
  member  = "serviceAccount:${google_service_account.asset_counter.email}"
}

# Grant Viewer role (for reading resource details)
resource "google_project_iam_member" "viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.asset_counter.email}"
}

# Grant access to additional projects (if specified)
resource "google_project_iam_member" "additional_asset_viewer" {
  for_each = toset(var.additional_project_ids)
  project  = each.value
  role     = "roles/cloudasset.viewer"
  member   = "serviceAccount:${google_service_account.asset_counter.email}"
}

resource "google_project_iam_member" "additional_viewer" {
  for_each = toset(var.additional_project_ids)
  project  = each.value
  role     = "roles/viewer"
  member   = "serviceAccount:${google_service_account.asset_counter.email}"
}

# Create service account key (optional)
resource "google_service_account_key" "asset_counter_key" {
  count              = var.create_key ? 1 : 0
  service_account_id = google_service_account.asset_counter.name
}

# Save the key to a file
resource "local_file" "service_account_key" {
  count           = var.create_key ? 1 : 0
  content         = base64decode(google_service_account_key.asset_counter_key[0].private_key)
  filename        = "${path.module}/gcp-asset-counter-key.json"
  file_permission = "0600"
}

# Outputs
output "service_account_email" {
  description = "Email of the created service account"
  value       = google_service_account.asset_counter.email
}

output "service_account_id" {
  description = "ID of the created service account"
  value       = google_service_account.asset_counter.id
}

output "service_account_key_file" {
  description = "Path to the service account key file"
  value       = var.create_key ? local_file.service_account_key[0].filename : "No key created"
}

output "usage_instructions" {
  description = "Instructions for using the service account"
  value = <<-EOT
    Service Account Created Successfully!
    
    Service Account Email: ${google_service_account.asset_counter.email}
    
    To use with Asset Counter:
    
    1. Add to gcp_config.ini:
       [default]
       auth_method = service_account
       service_account_file = ${var.create_key ? abspath("${path.module}/gcp-asset-counter-key.json") : "/path/to/key.json"}
    
    2. Or set environment variable:
       export GOOGLE_APPLICATION_CREDENTIALS="${var.create_key ? abspath("${path.module}/gcp-asset-counter-key.json") : "/path/to/key.json"}"
    
    3. Run the script:
       python gcp-asset-counter.py
    
    Security Note: Keep the key file secure and never commit to version control!
  EOT
}

# ==================================================================================
# DEPLOYMENT INSTRUCTIONS
# ==================================================================================
#
# Prerequisites:
# --------------
# 1. Install Terraform: https://www.terraform.io/downloads
# 2. Install gcloud CLI: https://cloud.google.com/sdk/docs/install
# 3. Authenticate with GCP:
#    gcloud auth application-default login
# 4. Enable required APIs:
#    gcloud services enable iam.googleapis.com
#    gcloud services enable cloudresourcemanager.googleapis.com
#    gcloud services enable cloudasset.googleapis.com
#
#
# Basic Deployment:
# ----------------
# 1. Initialize Terraform:
#    terraform init
#
# 2. Review the plan:
#    terraform plan -var="project_id=your-project-id"
#
# 3. Apply the configuration:
#    terraform apply -var="project_id=your-project-id"
#
# 4. Confirm by typing 'yes'
#
#
# Multi-Project Deployment:
# ------------------------
# terraform apply \
#   -var="project_id=main-project-id" \
#   -var="additional_project_ids=[\"project-2-id\",\"project-3-id\"]"
#
#
# Without Creating Key (use ADC instead):
# ---------------------------------------
# terraform apply \
#   -var="project_id=your-project-id" \
#   -var="create_key=false"
#
#
# Destroy Resources:
# -----------------
# terraform destroy -var="project_id=your-project-id"
#
#
# ==================================================================================
# MANUAL SETUP INSTRUCTIONS (Without Terraform)
# ==================================================================================
#
# Step 1: Enable Required APIs
# -----------------------------
# gcloud services enable cloudasset.googleapis.com
# gcloud services enable cloudresourcemanager.googleapis.com
#
#
# Step 2: Create Service Account
# -------------------------------
# gcloud iam service-accounts create asset-counter \
#   --display-name="Asset Counter Service Account" \
#   --description="Service account for cloud asset inventory" \
#   --project=YOUR_PROJECT_ID
#
#
# Step 3: Grant Required Roles
# -----------------------------
# # Cloud Asset Viewer (primary role)
# gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/cloudasset.viewer"
#
# # Viewer (for resource details)
# gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/viewer"
#
# # Browser (for listing projects - optional for multi-project)
# gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/browser"
#
#
# Step 4: Create Service Account Key
# -----------------------------------
# gcloud iam service-accounts keys create gcp-asset-counter-key.json \
#   --iam-account=asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com
#
# # Set file permissions
# chmod 600 gcp-asset-counter-key.json
#
#
# Step 5: Test Service Account
# -----------------------------
# export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/gcp-asset-counter-key.json"
# gcloud auth activate-service-account --key-file=gcp-asset-counter-key.json
# gcloud projects list
#
#
# ==================================================================================
# ORGANIZATION-LEVEL ACCESS (For Scanning All Projects)
# ==================================================================================
#
# Grant roles at organization level to scan all projects:
#
# gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/cloudasset.viewer"
#
# gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/viewer"
#
# Note: Requires Organization Admin permissions
#
#
# ==================================================================================
# FOLDER-LEVEL ACCESS (For Scanning Projects in Folder)
# ==================================================================================
#
# Grant roles at folder level:
#
# gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/cloudasset.viewer"
#
# gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/viewer"
#
#
# ==================================================================================
# CUSTOM ROLE (Minimal Permissions)
# ==================================================================================
#
# If you want minimal permissions instead of predefined roles:
#
# Step 1: Create custom role YAML file (asset-counter-role.yaml):
# ----------------------------------------------------------------
# title: "Asset Counter Custom Role"
# description: "Minimal permissions for asset counting"
# stage: "GA"
# includedPermissions:
# - cloudasset.assets.searchAllResources
# - resourcemanager.projects.get
# - resourcemanager.projects.list
# - resourcemanager.organizations.get
# - resourcemanager.folders.get
# - resourcemanager.folders.list
#
# Step 2: Create the role:
# -------------------------
# gcloud iam roles create assetCounterRole \
#   --project=YOUR_PROJECT_ID \
#   --file=asset-counter-role.yaml
#
# Step 3: Assign the role:
# -------------------------
# gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="projects/YOUR_PROJECT_ID/roles/assetCounterRole"
#
#
# ==================================================================================
# KEY ROTATION
# ==================================================================================
#
# List existing keys:
# gcloud iam service-accounts keys list \
#   --iam-account=asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com
#
# Create new key:
# gcloud iam service-accounts keys create new-key.json \
#   --iam-account=asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com
#
# Delete old key:
# gcloud iam service-accounts keys delete KEY_ID \
#   --iam-account=asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com
#
#
# ==================================================================================
# CLEANUP
# ==================================================================================
#
# Delete service account key:
# gcloud iam service-accounts keys delete KEY_ID \
#   --iam-account=asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com
#
# Remove IAM bindings:
# gcloud projects remove-iam-policy-binding YOUR_PROJECT_ID \
#   --member="serviceAccount:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
#   --role="roles/cloudasset.viewer"
#
# Delete service account:
# gcloud iam service-accounts delete \
#   asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com
#
#
# ==================================================================================
# SECURITY BEST PRACTICES
# ==================================================================================
#
# 1. Use Workload Identity Federation (preferred for automation from other clouds)
# 2. Rotate service account keys regularly (every 90 days)
# 3. Use short-lived tokens when possible
# 4. Never commit service account keys to version control
# 5. Store keys in Secret Manager or Key Vault
# 6. Set key file permissions to 600 (read/write for owner only)
# 7. Audit service account usage with Cloud Audit Logs
# 8. Use least-privilege principle - only grant necessary permissions
# 9. Consider using Cloud Asset Inventory Export for large-scale operations
# 10. Enable VPC Service Controls for additional security
#
#
# ==================================================================================
# TROUBLESHOOTING
# ==================================================================================
#
# Error: "Permission denied on resource project"
# ----------------------------------------------
# Solution: Ensure service account has required roles and permissions have propagated
# (wait 60 seconds after granting roles)
#
# Error: "API [cloudasset.googleapis.com] not enabled"
# ----------------------------------------------------
# Solution: Enable the API:
# gcloud services enable cloudasset.googleapis.com
#
# Error: "The caller does not have permission"
# --------------------------------------------
# Solution: Your user account needs appropriate permissions to create service accounts
# and grant roles (roles/iam.serviceAccountAdmin, roles/iam.roleAdmin)
#
# Verify service account permissions:
# gcloud projects get-iam-policy YOUR_PROJECT_ID \
#   --flatten="bindings[].members" \
#   --filter="bindings.members:asset-counter@YOUR_PROJECT_ID.iam.gserviceaccount.com"
#
# Test service account authentication:
# gcloud auth activate-service-account --key-file=gcp-asset-counter-key.json
# gcloud projects list
#
# ==================================================================================







