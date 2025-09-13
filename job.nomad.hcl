job "rfinger" {
  type = "service"

  group "rfinger" {
    network {
      port "http" { }
    }

    service {
      name     = "rfinger"
      port     = "http"
      provider = "nomad"
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.rfinger.rule=Host(`rfinger.datasektionen.se`)",
        "traefik.http.routers.rfinger.tls.certresolver=default",
      ]
    }

    task "rfinger" {
      driver = "docker"

      config {
        image = var.image_tag
        ports = ["http"]
      }

      template {
        data        = <<ENV
{{ with nomadVar "nomad/jobs/rfinger" }}
AWS_ACCESS_KEY_ID={{ .aws_access_id }}
AWS_SECRET_ACCESS_KEY={{ .aws_access_key }}
APP_SECRET={{ .app_secret }}
HIVE_SECRET={{ .hive_api_key }}
OIDC_SECRET={{ .oidc_secret }}
{{ end }}
PORT={{ env "NOMAD_PORT_http" }}
RUST_LOG=info
S3_BUCKET=zfinger
OIDC_ID=rfinger
OIDC_PROVIDER=https://sso.datasektionen.se/op
REDIRECT_URL=https://rfinger.datasektionen.se/auth/oidc/callback
HIVE_URL=https://hive.datasektionen.se/api/v1
ENV
        destination = "local/.env"
        env         = true
      }

      resources {
        memory = 120
      }
    }
  }
}

variable "image_tag" {
  type = string
  default = "ghcr.io/datasektionen/rfinger:latest"
}
