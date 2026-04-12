FROM golang:1.22-alpine AS govulncheck-builder
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

FROM python:3.13-slim
WORKDIR /app

# Install system dependencies and Trivy via its official apt repository
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates wget gnupg \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

COPY --from=govulncheck-builder /go/bin/govulncheck /usr/local/bin/govulncheck

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
