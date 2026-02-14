#!/usr/bin/env bash
# SecureFlow AI — Azure Container Apps deployment script
#
# Prerequisites:
#   - Azure CLI logged in (az login)
#   - Docker installed
#   - Environment variables set (see .env.example)
#
# Usage:
#   chmod +x infra/deploy.sh
#   ./infra/deploy.sh

set -euo pipefail

# ─── Configuration ─────────────────────────────────────────────
RG="${AZURE_RG:-secureflow-rg}"
LOCATION="${AZURE_LOCATION:-eastus2}"
ACR_NAME="${AZURE_ACR:-secureflowacr}"
APP_NAME="${AZURE_APP:-secureflow-ai}"
IMAGE_TAG="${IMAGE_TAG:-v1}"
LOG_ANALYTICS="${LOG_ANALYTICS_NAME:-secureflow-logs}"
ENV_NAME="${CONTAINER_ENV:-secureflow-env}"

echo "=== SecureFlow AI Deployment ==="
echo "Resource Group: $RG"
echo "Location: $LOCATION"
echo "ACR: $ACR_NAME"
echo "App: $APP_NAME"
echo ""

# ─── Step 1: Resource Group ───────────────────────────────────
echo ">>> Creating resource group..."
az group create --name "$RG" --location "$LOCATION" --output none

# ─── Step 2: Container Registry ───────────────────────────────
echo ">>> Creating Azure Container Registry..."
az acr create \
    --resource-group "$RG" \
    --name "$ACR_NAME" \
    --sku Basic \
    --admin-enabled true \
    --output none

# ─── Step 3: Build and push image ─────────────────────────────
echo ">>> Building and pushing container image..."
az acr build \
    --registry "$ACR_NAME" \
    --image "secureflow-ai:$IMAGE_TAG" \
    --file Dockerfile \
    .

# ─── Step 4: Log Analytics workspace ──────────────────────────
echo ">>> Creating Log Analytics workspace..."
az monitor log-analytics workspace create \
    --resource-group "$RG" \
    --workspace-name "$LOG_ANALYTICS" \
    --output none

LOG_ID=$(az monitor log-analytics workspace show \
    --resource-group "$RG" \
    --workspace-name "$LOG_ANALYTICS" \
    --query customerId -o tsv)
LOG_KEY=$(az monitor log-analytics workspace get-shared-keys \
    --resource-group "$RG" \
    --workspace-name "$LOG_ANALYTICS" \
    --query primarySharedKey -o tsv)

# ─── Step 5: Container Apps environment ───────────────────────
echo ">>> Creating Container Apps environment..."
az containerapp env create \
    --name "$ENV_NAME" \
    --resource-group "$RG" \
    --location "$LOCATION" \
    --logs-workspace-id "$LOG_ID" \
    --logs-workspace-key "$LOG_KEY" \
    --output none

# ─── Step 6: Get ACR credentials ──────────────────────────────
ACR_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
ACR_USER=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
ACR_PASS=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

# ─── Step 7: Deploy Container App ─────────────────────────────
echo ">>> Deploying Container App..."
az containerapp create \
    --name "$APP_NAME" \
    --resource-group "$RG" \
    --environment "$ENV_NAME" \
    --image "${ACR_SERVER}/secureflow-ai:${IMAGE_TAG}" \
    --registry-server "$ACR_SERVER" \
    --registry-username "$ACR_USER" \
    --registry-password "$ACR_PASS" \
    --target-port 8000 \
    --ingress external \
    --min-replicas 0 \
    --max-replicas 3 \
    --cpu 1.0 \
    --memory 2.0Gi \
    --env-vars \
        "AZURE_OPENAI_ENDPOINT=secretref:azure-openai-endpoint" \
        "AZURE_OPENAI_API_KEY=secretref:azure-openai-key" \
        "AZURE_OPENAI_DEPLOYMENT=${AZURE_OPENAI_DEPLOYMENT:-gpt-4o}" \
        "COSMOS_ENDPOINT=secretref:cosmos-endpoint" \
        "COSMOS_KEY=secretref:cosmos-key" \
        "COSMOS_DATABASE=${COSMOS_DATABASE:-secureflow}" \
        "GITHUB_TOKEN=secretref:github-token" \
        "GITHUB_WEBHOOK_SECRET=secretref:github-webhook-secret" \
        "APPINSIGHTS_CONNECTION_STRING=secretref:appinsights-conn" \
        "LOG_LEVEL=${LOG_LEVEL:-INFO}" \
    --output none

# ─── Step 8: Show the URL ─────────────────────────────────────
FQDN=$(az containerapp show \
    --name "$APP_NAME" \
    --resource-group "$RG" \
    --query properties.configuration.ingress.fqdn -o tsv)

echo ""
echo "=== Deployment Complete ==="
echo "App URL: https://$FQDN"
echo "Health:  https://$FQDN/health"
echo "Webhook: https://$FQDN/webhook"
echo ""
echo "IMPORTANT: Set secrets via Azure Portal or CLI:"
echo "  az containerapp secret set --name $APP_NAME --resource-group $RG \\"
echo "    --secrets azure-openai-endpoint=<value> azure-openai-key=<value> \\"
echo "    cosmos-endpoint=<value> cosmos-key=<value> \\"
echo "    github-token=<value> github-webhook-secret=<value> \\"
echo "    appinsights-conn=<value>"
echo ""
echo "Then update the GitHub webhook URL to: https://$FQDN/webhook"
