package util

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

var aliases []string

// RedactOutput aktif olduğunda ekrana basılan secret değerlerini maskeler
var RedactOutput bool

// Kabuk içinde yerleşik (built-in) bulunan komutlar PATH'te ayrı binary olmayabilir
var shellBuiltins = map[string]bool{
	"cd": true, "export": true, "history": true, "source": true,
	"alias": true, "unalias": true, "unset": true, "set": true,
	"exit": true, "logout": true, "pwd": true, "echo": true,
	"read": true, "type": true, "ulimit": true, "umask": true,
	"wait": true, "eval": true, "exec": true, "fg": true,
	"bg": true, "jobs": true, "test": true, "true": true,
	"false": true, "sudo": true, "time": true, "builtin": true,
	"command": true, "declare": true, "local": true, "typeset": true,
	"shopt": true, "setopt": true, "unsetopt": true, "bindkey": true,
	"autoload": true, "zmodload": true, "hash": true, "help": true,
	// Fish shell yerleşik komutları
	"abbr": true, "fish_add_path": true, "set_color": true,
	"functions": true, "funcsave": true, "funced": true,
	"string": true, "math": true, "status": true, "argparse": true,
	"contains": true, "begin": true, "end": true, "and": true,
	"or": true, "not": true, "switch": true, "case": true,
	":": true, ".": true, "[": true,
}

// Regex'leri her satırda tekrar derlememek için başlangıçta bir kere derliyoruz.
// Ayrıca mükerrer olan Google/AWS pattern'leri birleştirildi ve güncel AI, Cloud, DevOps token'ları eklendi.
var secretPatterns = map[string]string{
	// --- AI, LLM & Machine Learning Servisleri ---
	"OpenAI API Key":              `sk-(?:proj-[0-9a-zA-Z\-_]{20,}|svcacct-[0-9a-zA-Z\-_]{20,}|[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20})`,
	"Anthropic (Claude) API Key":  `sk-ant-[A-Za-z0-9_-]{30,}`,
	"HuggingFace Access Token":    `hf_[a-zA-Z0-9]{30,}`,
	"Groq API Key":                `gsk_[a-zA-Z0-9]{48,}`,
	"Perplexity AI API Key":       `pplx-[a-zA-Z0-9]{40,}`,
	"Replicate API Token":         `r8_[a-zA-Z0-9]{36,}`,
	"Fireworks AI API Key":        `fw_[a-zA-Z0-9]{24,}`,
	"LangSmith / LangChain Key":   `lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}`,
	"Cohere API Key":              `(?i)cohere.*['"][a-zA-Z0-9]{40}['"]`,
	"Mistral AI API Key":          `(?i)mistral.*['"][a-zA-Z0-9]{32}['"]`,
	"DeepSeek API Key":            `(?i)deepseek.*['"]sk-[a-f0-9]{32}['"]`,
	"ElevenLabs API Key":          `(?i)elevenlabs.*['"][a-f0-9]{32}['"]`,
	"Pinecone API Key":            `pcsk_[a-zA-Z0-9_]{50,}`,
	"Tavily AI API Key":           `tvly-[a-zA-Z0-9\-_]{30,}`,
	"Voyage AI API Key":           `pa-[a-zA-Z0-9\-_]{40,}`,
	"Weights Biases API Key":      `(?i)(?:wandb|weights.and.biases)[^\r\n]{0,40}['"]?[a-f0-9]{40}['"]?`,
	"Modal API Secret":            `(?i)modal[_-]?(?:token|secret)[^\r\n]{0,30}['"][A-Za-z0-9_-]{20,}['"]`,
	"RunPod API Key":              `(?i)runpod[^\r\n]{0,30}['"][A-Za-z0-9_-]{30,}['"]`,
	"Together AI API Key":         `(?i)together[_-]?(?:api[_-]?)?key[ \t]*[:=][ \t]*['"]?[A-Za-z0-9_-]{32,}`,
	"Stability AI API Key":        `(?i)stability[^\r\n]{0,30}sk-[A-Za-z0-9]{40,}`,
	"AssemblyAI API Key":          `(?i)assemblyai[^\r\n]{0,30}['"][A-Za-z0-9]{32}['"]`,
	"Deepgram API Key":            `(?i)deepgram[^\r\n]{0,30}['"][A-Fa-f0-9]{40}['"]`,
	"OpenRouter API Key":          `sk-or-v1-[a-f0-9]{64}`,
	"Google Vertex AI Credential": `(?i)vertex[_-]?(?:ai)?[^\r\n]{0,40}['"][A-Za-z0-9_-]{30,}['"]`,
	"Milvus Token Assignment":     `(?i)milvus[_-]?(?:token|password)[ \t]*[:=][ \t]*['"][^'"\r\n]{8,}['"]`,
	"Weaviate API Key Assignment": `(?i)weaviate[_-]?(?:api[_-]?)?key[ \t]*[:=][ \t]*['"][^'"\r\n]{16,}['"]`,
	"Qdrant API Key Assignment":   `(?i)qdrant[_-]?(?:api[_-]?)?key[ \t]*[:=][ \t]*['"][^'"\r\n]{16,}['"]`,

	// --- Cloud & Altyapı Sağlayıcıları ---
	"AWS Access Key ID":             `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
	"AWS Secret Access Key":         `(?i)aws_secret_access_key[\s=:]+['"]?[0-9a-zA-Z/+]{40}['"]?`,
	"AWS Session Token":             `(?i)aws_session_token[ \t]*[:=][ \t]*['"]?[A-Za-z0-9/+=]{100,}`,
	"AWS Credentials Section":       `(?m)^\[(?:default|profile[ \t]+[^\]]+)\][ \t]*$`,
	"Amazon MWS Auth Token":         `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"Google / Gemini API Key":       `AIza[0-9A-Za-z\-_]{35}`,
	"Google Cloud OAuth":            `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"Google OAuth Client Secret":    `(?i)client_secret[ \t]*[:=][ \t]*["']?GOCSPX-[A-Za-z0-9_-]{20,}`,
	"Google (GCP) Service-account":  `"type":\s*"service_account"`,
	"Google OAuth Access Token":     `ya29\.[0-9A-Za-z\-_]+`,
	"GCP Refresh Token":             `(?i)refresh_token[ \t]*[:=][ \t]*["']?1//[A-Za-z0-9_-]{20,}`,
	"Azure Storage Account Key":     `(?i)DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]+`,
	"Azure SAS Token":               `sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=[^&\s]+&sig=[A-Za-z0-9%+/=]+`,
	"Azure Client Secret":           `(?i)(?:AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET)[ \t]*[:=][ \t]*['"]?[^'"\s]{16,}`,
	"Azure Service Principal":       `(?i)(?:client_secret|clientSecret)[ \t]*[:=][ \t]*['"][A-Za-z0-9~._-]{20,}['"]`,
	"DigitalOcean Personal Token":   `dop_v1_[a-f0-9]{64}`,
	"DigitalOcean OAuth Token":      `doo_v1_[a-f0-9]{64}`,
	"DigitalOcean Refresh Token":    `dor_v1_[a-f0-9]{64}`,
	"Alibaba Cloud AccessKey ID":    `LTAI[a-zA-Z0-9]{16,20}`,
	"Oracle OCI Fingerprint":        `(?i)fingerprint[ \t]*[:=][ \t]*['"]?[a-f0-9]{2}(?::[a-f0-9]{2}){15}`,
	"Cloudflare API Token":          `(?i)cloudflare.*['"][A-Za-z0-9_\-]{40}['"]`,
	"Cloudflare Global API Key":     `(?i)(?:cloudflare|CF_API_KEY)[^\r\n]{0,30}['"][A-Fa-f0-9]{37}['"]`,
	"Cloudflare R2 Secret Key":      `(?i)(?:r2_secret_access_key|cloudflare_r2_secret)[ \t]*[:=][ \t]*['"]?[A-Za-z0-9/+=]{40}`,
	"Cloudflare Tunnel Token":       `(?i)TUNNEL_TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{80,}`,
	"Tailscale API Key":             `tskey-api-[A-Za-z0-9_-]{20,}`,
	"Tailscale Auth Key":            `tskey-auth-[A-Za-z0-9_-]{20,}`,
	"Tailscale OAuth Client Secret": `tskey-client-[A-Za-z0-9_-]{20,}`,
	"Heroku API Key":                `[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
	"Vercel Access Token":           `(?i)vercel.*['"][a-zA-Z0-9]{24}['"]`,
	"Netlify Personal Token":        `(?i)(?:netlify|NETLIFY_AUTH_TOKEN)[^\r\n]{0,30}['"][A-Za-z0-9_-]{30,}['"]`,
	"Fastly API Token":              `(?i)(?:fastly|FASTLY_API_TOKEN)[^\r\n]{0,30}['"][A-Za-z0-9_-]{20,}['"]`,
	"Akamai EdgeGrid Secret":        `(?i)client_secret[ \t]*=[ \t]*[A-Za-z0-9_-]{20,}`,
	"Supabase Access Token":         `sbp_[a-f0-9]{40}`,
	"PlanetScale API Token":         `pscale_tkn_[a-zA-Z0-9_\-\.]{32,}`,
	"PlanetScale Password":          `pscale_pw_[a-zA-Z0-9_\-\.]{32,}`,
	"Render API Key":                `rnd_[a-zA-Z0-9]{28,}`,
	"Fly.io Access Token":           `fo1_[a-zA-Z0-9\-_]{40,}`,
	"Cloudinary URL":                `cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[A-Za-z0-9\-_]+`,
	"Firebase URL":                  `.*firebaseio\.com`,

	// --- Kubernetes & Container Güvenliği ---
	"Kubernetes Secret Manifest":    `(?m)^[ \t]*kind:[ \t]*Secret[ \t]*$`,
	"Kubernetes Docker Config":      `\.dockerconfigjson[ \t]*:[ \t]*[A-Za-z0-9+/=]{20,}`,
	"Kubernetes Basic Auth Data":    `(?m)^[ \t]*(?:username|password|token):[ \t]*[A-Za-z0-9+/=]{16,}[ \t]*$`,
	"Kubeconfig Client Key Data":    `client-key-data:[ \t]*[A-Za-z0-9+/=]{100,}`,
	"Kubeconfig Client Certificate": `client-certificate-data:[ \t]*[A-Za-z0-9+/=]{100,}`,
	"Kubeconfig Bearer Token":       `(?m)^[ \t]*token:[ \t]*['"]?[A-Za-z0-9._-]{30,}`,
	"Helm Values Password":          `(?i)(?:password|secretKey|apiKey)[ \t]*:[ \t]*['"][^'"\r\n]{8,}['"]`,
	"Docker Registry Auth":          `"auth"[ \t]*:[ \t]*"[A-Za-z0-9+/=]{16,}"`,
	"Docker Config Auths":           `"auths"[ \t]*:[ \t]*\{`,
	"Docker Build Argument Secret":  `(?i)(?:ARG|ENV)[ \t]+(?:[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|API_KEY))[ \t]*=?[ \t]*[^ \t\r\n]{8,}`,
	"Harbor Robot Account":          `robot\$[A-Za-z0-9_-]+`,
	"Traefik Basic Auth":            `(?i)basicauth[^\r\n]{0,50}(?:\$2[aby]\$|\$apr1\$)[^\s'"]+`,
	"NGINX Basic Auth Hash":         `\$apr1\$[A-Za-z0-9./$]+`,

	// --- Git, CI/CD & DevOps Araçları ---
	"GitHub Personal Access Token":    `gh[pousr]_[0-9a-zA-Z]{36}`,
	"GitHub Fine-Grained Token":       `github_pat_[0-9a-zA-Z_]{82}`,
	"GitHub Legacy Token":             `[g|G][i|I][t|T][h|H][u|U][b|B].*['|"][0-9a-zA-Z]{35,40}['|"]`,
	"GitHub Actions Token Assignment": `(?i)GITHUB_TOKEN[ \t]*[:=][ \t]*['"]?gh[A-Za-z0-9_]{30,}`,
	"GitLab Personal Access Token":    `glpat-[0-9a-zA-Z\-_]{20}`,
	"GitLab Pipeline Trigger":         `glptt-[0-9a-f]{40}`,
	"GitLab Runner Token":             `glrt-[0-9a-zA-Z\-_]{20}`,
	"GitLab Deploy Token":             `gldt-[0-9a-zA-Z\-_]{20}`,
	"GitLab CI Job Token":             `(?i)CI_JOB_TOKEN[ \t]*[:=][ \t]*['"]?[A-Za-z0-9_-]{16,}`,
	"GitLab Agent Token":              `glagent-[A-Za-z0-9_-]{20,}`,
	"GitLab Feed Token":               `glft-[A-Za-z0-9_-]{20,}`,
	"GitLab OAuth Token":              `gloas-[A-Za-z0-9_-]{20,}`,
	"Bitbucket App Password":          `ATBB[a-zA-Z0-9]{24,}`,
	"NPM Access Token":                `npm_[A-Za-z0-9]{36}`,
	"PyPI Upload Token":               `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`,
	"Docker Hub PAT":                  `dckr_pat_[a-zA-Z0-9\-_]{27,}`,
	"Jenkins API Token":               `(?i)jenkins[^\r\n]{0,40}['"][a-f0-9]{32}['"]`,
	"CircleCI Personal Token":         `(?i)circleci[^\r\n]{0,40}['"][a-f0-9]{40}['"]`,
	"Travis CI Token":                 `(?i)travis[^\r\n]{0,40}['"][A-Za-z0-9_-]{20,}['"]`,
	"Buildkite Agent Token":           `(?i)BUILDKITE_AGENT_TOKEN[ \t]*=[ \t]*['"]?[A-Fa-f0-9]{40}`,
	"Buildkite API Token":             `(?i)BUILDKITE_API_TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{30,}`,
	"ArgoCD Auth Token":               `(?i)argocd[^\r\n]{0,40}eyJ[A-Za-z0-9_-]{20,}`,
	"ArgoCD Admin Password":           `(?i)argocd[^\r\n]{0,30}(?:password|passwd)[ \t]*[:=][ \t]*['"][^'"\r\n]{8,}['"]`,
	"Ansible Vault Header":            `\$ANSIBLE_VAULT;1\.[12];AES256`,
	"Ansible Password Variable":       `(?i)ansible_(?:password|ssh_pass|become_pass)[ \t]*[:=][ \t]*['"][^'"\r\n]{4,}['"]`,
	"HashiCorp Terraform Token":       `[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{30,}`,
	"Terraform Variable Secret":       `(?i)(?:variable|TF_VAR_)[^\r\n]{0,60}(?:password|secret|token)[^\r\n]{0,40}['"][^'"\r\n]{8,}['"]`,
	"HashiCorp Vault Token":           `hvs\.[A-Za-z0-9_-]{20,}`,
	"Vault Batch Token":               `hvb\.[A-Za-z0-9_-]{20,}`,
	"Consul ACL Token Assignment":     `(?i)CONSUL_HTTP_TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{20,}`,
	"Nomad ACL Token Assignment":      `(?i)NOMAD_TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{20,}`,
	"Pulumi Access Token":             `pul-[a-f0-9]{40}`,
	"Databricks Access Token":         `dapi[a-f0-9]{32}`,
	"Postman API Key":                 `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`,
	"Doppler Service Token":           `dp\.(?:st|pt|ct)\.[a-zA-Z0-9_\-]{40,}`,
	"Grafana API Key":                 `eyJrIjoi[A-Za-z0-9\-_=]{70,}`,
	"Grafana Cloud API Token":         `glc_[A-Za-z0-9+/]{32,}=*`,
	"Grafana Service Account":         `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`,
	"New Relic User Key":              `NRAK-[A-Z0-9]{27}`,
	"Sentry Auth Token":               `sntrys_[A-Za-z0-9+/=]{60,}`,
	"Datadog API Key":                 `(?i)datadog.*['"][a-f0-9]{32}['"]`,
	"Linear API Key":                  `lin_api_[a-zA-Z0-9]{40}`,
	"SonarQube Token":                 `squ_[a-f0-9]{40}`,
	"JFrog Access Token":              `(?i)jfrog[^\r\n]{0,40}eyJ[A-Za-z0-9_-]{20,}`,
	"Artifactory API Key":             `(?i)artifactory[^\r\n]{0,40}['"][A-Za-z0-9_-]{30,}['"]`,
	"Snyk API Token":                  `(?i)snyk[^\r\n]{0,40}['"][a-f0-9-]{36}['"]`,
	"Codecov Upload Token":            `(?i)CODECOV_TOKEN[ \t]*=[ \t]*['"]?[a-f0-9-]{36}`,
	"Coveralls Repo Token":            `(?i)COVERALLS_REPO_TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{20,}`,

	// --- Veritabanı, Depolama & Mesaj Kuyruğu ---
	"PostgreSQL Connection URI":    `postgres(?:ql)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"MySQL Connection URI":         `mysql://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"MongoDB Connection URI":       `mongodb(?:\+srv)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"Redis Connection URI":         `redis(?:s)?://[^/\s:@]*:[^/\s:@]+@[^/\s]+`,
	"RabbitMQ (AMQP) URI":          `amqp(?:s)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"Microsoft SQL Server URI":     `(?i)sqlserver://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"Oracle Database URI":          `(?i)oracle://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"CouchDB Connection URI":       `(?i)couchdbs?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"Neo4j Connection URI":         `(?i)neo4j(?:\+s|\+ssc)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"ClickHouse Connection URI":    `(?i)clickhouse(?:s)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"InfluxDB Token Assignment":    `(?i)INFLUXDB(?:_V2)?_TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{30,}`,
	"Elasticsearch URI":            `(?i)https?://[^/\s:@]+:[^/\s:@]+@[^/\s]*elastic[^/\s]*`,
	"Elasticsearch API Key":        `(?i)(?:elastic_api_key|ELASTICSEARCH_API_KEY)[ \t]*[:=][ \t]*['"]?[A-Za-z0-9+/=]{20,}`,
	"Redis Password Assignment":    `(?i)(?:REDIS_PASSWORD|requirepass)[ \t=:]+['"]?[^'"\s]{8,}`,
	"Kafka SASL Password":          `(?i)sasl\.jaas\.config[ \t]*=[^\r\n]{0,200}password[ \t]*=[ \t]*\\?"[^"\r\n]+`,
	"RabbitMQ Password":            `(?i)RABBITMQ_DEFAULT_PASS[ \t]*=[ \t]*['"]?[^'"\s]{8,}`,
	"MinIO Root Password":          `(?i)MINIO_ROOT_PASSWORD[ \t]*=[ \t]*['"]?[^'"\s]{8,}`,
	"MinIO Secret Key":             `(?i)MINIO_SECRET_KEY[ \t]*=[ \t]*['"]?[^'"\s]{8,}`,
	"S3 Compatible Secret Key":     `(?i)(?:S3_SECRET_KEY|S3_SECRET_ACCESS_KEY)[ \t]*[:=][ \t]*['"]?[A-Za-z0-9/+=]{20,}`,
	"Backblaze B2 Application Key": `(?i)(?:B2_APPLICATION_KEY|BACKBLAZE_APPLICATION_KEY)[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{20,}`,
	"Password in URL":              `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]?`,

	// --- İletişim, Kimlik Doğrulama & SaaS Servisleri ---
	"Slack Token":                   `(xox[p|b|o|a|r|s]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9\-_]{24,})`,
	"Slack App Level Token":         `xapp-[0-9]+-[A-Za-z0-9-]{20,}`,
	"Slack Configuration Token":     `xoxe\.xox[bp]-[A-Za-z0-9.-]{20,}`,
	"Slack Refresh Token":           `xoxe-[0-9]+-[A-Za-z0-9-]{20,}`,
	"Slack Webhook":                 `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}`,
	"Discord Webhook":               `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z\-_]{60,}`,
	"Discord Bot Token":             `(?i)discord[_-]?(?:bot[_-]?)?token[ \t]*[:=][ \t]*['"][A-Za-z0-9._-]{50,}['"]`,
	"Telegram Bot Token":            `[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}`,
	"Microsoft Teams Webhook":       `https://[A-Za-z0-9.-]+(?:webhook\.office\.com|logic\.azure\.com)/[^\s'"]{30,}`,
	"Microsoft Graph Client Secret": `(?i)(?:GRAPH_CLIENT_SECRET|MS_GRAPH_SECRET)[ \t]*[:=][ \t]*['"]?[^'"\s]{16,}`,
	"Firebase Cloud Messaging Key":  `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{100,}`,
	"Firebase Admin Private Key":    `(?i)"private_key"[ \t]*:[ \t]*"-----BEGIN PRIVATE KEY-----`,
	"Auth0 Client Secret":           `(?i)AUTH0_CLIENT_SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{30,}`,
	"Okta API Token":                `(?i)SSWS[ \t]+[A-Za-z0-9_-]{20,}`,
	"Keycloak Client Secret":        `(?i)KEYCLOAK_CLIENT_SECRET[ \t]*[:=][ \t]*['"]?[A-Za-z0-9_-]{20,}`,
	"Clerk Secret Key":              `sk_(?:live|test)_[A-Za-z0-9_-]{20,}`,
	"Resend API Key":                `re_[A-Za-z0-9_-]{20,}`,
	"Brevo API Key":                 `xkeysib-[A-Za-z0-9_-]{30,}`,
	"Postmark Server Token":         `(?i)POSTMARK_SERVER_TOKEN[ \t]*=[ \t]*['"]?[a-f0-9-]{36}`,
	"Pusher App Secret":             `(?i)PUSHER_APP_SECRET[ \t]*=[ \t]*['"]?[a-f0-9]{20,}`,
	"Algolia Admin API Key":         `(?i)ALGOLIA_ADMIN_API_KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20,}`,
	"Algolia Search API Key":        `(?i)ALGOLIA_SEARCH_API_KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20,}`,
	"SendGrid API Key":              `SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`,
	"MailChimp API Key":             `[0-9a-f]{32}-us[0-9]{1,2}`,
	"Mailgun API Key":               `key-[0-9a-zA-Z]{32}`,
	"Twilio API Key":                `SK[0-9a-fA-F]{32}`,
	"Notion Integration Token":      `(?:secret_[a-zA-Z0-9]{43}|ntn_[0-9a-zA-Z]{46,})`,
	"Airtable Personal Token":       `pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}`,
	"Mapbox Secret Token":           `sk\.eyJ1Ijoi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+`,
	"Facebook Access Token":         `EAACEdEose0cBA[0-9A-Za-z]+`,
	"Facebook OAuth":                `[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|"][0-9a-f]{32}['|"]`,
	"Twitter Access Token":          `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
	"Twitter OAuth":                 `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|"][0-9a-zA-Z]{35,44}['|"]`,

	// --- Ödeme Sistemleri (Payment Providers) ---
	"Stripe Live API Key":           `sk_live_[0-9a-zA-Z]{24,}`,
	"Stripe Restricted API Key":     `rk_live_[0-9a-zA-Z]{24,}`,
	"Stripe Test Secret Key":        `sk_test_[A-Za-z0-9]{24,}`,
	"Stripe Test Restricted Key":    `rk_test_[A-Za-z0-9]{24,}`,
	"Stripe Publishable Live Key":   `pk_live_[A-Za-z0-9]{24,}`,
	"Stripe Webhook Secret":         `whsec_[0-9a-zA-Z]{32,}`,
	"Shopify Access Token":          `shpat_[a-fA-F0-9]{32}`,
	"Shopify Custom App Token":      `shpca_[a-fA-F0-9]{32}`,
	"Shopify Private App Password":  `shppa_[a-fA-F0-9]{32}`,
	"Shopify Shared Secret":         `shpss_[a-fA-F0-9]{32}`,
	"PayPal Braintree Access Token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"PayPal Client Secret":          `(?i)PAYPAL_CLIENT_SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{30,}`,
	"Square Access Token":           `sq0atp-[0-9A-Za-z\-_]{22}`,
	"Square OAuth Secret":           `sq0csp-[0-9A-Za-z\-_]{43}`,
	"Adyen API Key":                 `(?i)ADYEN_API_KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9_-]{30,}`,
	"Razorpay Live Secret":          `(?i)RAZORPAY_KEY_SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20,}`,
	"Iyzico Secret Key":             `(?i)(?:IYZICO_SECRET_KEY|IYZIPAY_SECRET_KEY)[ \t]*=[ \t]*['"]?[^'"\s]{16,}`,
	"PayTR Merchant Key":            `(?i)PAYTR_MERCHANT_KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9+/=]{16,}`,
	"PayTR Merchant Salt":           `(?i)PAYTR_MERCHANT_SALT[ \t]*=[ \t]*['"]?[A-Za-z0-9+/=]{8,}`,
	"Picatic API Key":               `sk_live_[0-9a-z]{32}`,

	// --- Kriptografik Anahtarlar, Kimlik & Genel Secret'lar ---
	"RSA Private Key":             `-----BEGIN RSA PRIVATE KEY-----`,
	"SSH (DSA) Private Key":       `-----BEGIN DSA PRIVATE KEY-----`,
	"EC Private Key":              `-----BEGIN EC PRIVATE KEY-----`,
	"OpenSSH Private Key":         `-----BEGIN OPENSSH PRIVATE KEY-----`,
	"PKCS8 Private Key":           `-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----`,
	"PGP Private Key Block":       `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"PKCS12 Base64 Data":          `(?i)(?:PKCS12|PFX_DATA)[ \t]*[:=][ \t]*['"]?[A-Za-z0-9+/=]{100,}`,
	"JSON Web Token (JWT)":        `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
	"JWT Bearer Header":           `(?i)Authorization[ \t]*:[ \t]*Bearer[ \t]+eyJ[A-Za-z0-9_-]{10,}`,
	"Bearer Token Header":         `(?i)Authorization[ \t]*:[ \t]*Bearer[ \t]+[A-Za-z0-9._~+/-]{20,}`,
	"Basic Authorization Header":  `(?i)Authorization[ \t]*:[ \t]*Basic[ \t]+[A-Za-z0-9+/=]{12,}`,
	"HTTP Proxy Credentials":      `(?i)https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"SSH Password Assignment":     `(?i)SSH_PASSWORD[ \t]*=[ \t]*['"]?[^'"\s]{8,}`,
	"Sudo Password Assignment":    `(?i)SUDO_PASSWORD[ \t]*=[ \t]*['"]?[^'"\s]{8,}`,
	"SMTP Password Assignment":    `(?i)SMTP_(?:PASS|PASSWORD)[ \t]*=[ \t]*['"]?[^'"\s]{8,}`,
	"SMTP Connection URI":         `(?i)smtps?://[^/\s:@]+:[^/\s:@]+@[^/\s]+`,
	"LDAP Bind Password":          `(?i)(?:LDAP_BIND_PASSWORD|LDAP_PASSWORD)[ \t]*[:=][ \t]*['"]?[^'"\s]{8,}`,
	"Generic API Key":             `[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|"][0-9a-zA-Z]{32,45}['|"]`,
	"Generic Secret":              `[s|S][e|E][c|C][r|R][e|E][t|T].*['|"][0-9a-zA-Z]{32,45}['|"]`,
	"Generic Password Assignment": `(?i)(?:password|passwd|pwd)[ \t]*[:=][ \t]*['"][^'"\r\n]{8,}['"]`,
	"Generic Token Assignment":    `(?i)(?:access_token|auth_token|api_token)[ \t]*[:=][ \t]*['"][A-Za-z0-9._-]{20,}['"]`,
	"Generic Secret Assignment":   `(?i)(?:client_secret|app_secret|secret_key)[ \t]*[:=][ \t]*['"][A-Za-z0-9._-]{16,}['"]`,
	"Secret Environment Variable": `(?i)(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*[ \t]*=[ \t]*['"]?[^'"\s]{12,}`,
}

var compiledRegexes map[string]*regexp.Regexp

func init() {
	compiledRegexes = make(map[string]*regexp.Regexp, len(secretPatterns))
	for label, pattern := range secretPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			compiledRegexes[label] = re
		}
	}
}

func isStringInArray(target string, array []string) bool {
	for _, element := range array {
		if element == target {
			return true
		}
	}
	return false
}

func IsAliasInConfigFile(configFile string) []string {
	aliases = nil

	data, err := os.ReadFile(configFile)
	if err != nil {
		color.Red("Error reading file: %v\n", err)
		return nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Yorum satırlarını ve boş satırları atla
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue
		}

		// Fish function tanımlaması (ör: function gco)
		if strings.HasPrefix(line, "function ") || strings.HasPrefix(line, "function\t") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				aliases = append(aliases, fields[1])
			}
			continue
		}

		if !strings.HasPrefix(line, "alias ") && !strings.HasPrefix(line, "alias\t") {
			continue
		}

		rest := strings.TrimSpace(line[len("alias"):])
		if strings.Contains(rest, "=") {
			// Standart bash/zsh/fish formatı: alias ll='ls -la'
			parts := strings.SplitN(rest, "=", 2)
			aliasName := strings.TrimSpace(parts[0])
			if aliasName != "" {
				aliases = append(aliases, aliasName)
			}
		} else {
			// Fish boşluklu alias formatı: alias ll 'ls -la'
			fields := strings.Fields(rest)
			if len(fields) >= 2 {
				aliases = append(aliases, fields[0])
			}
		}
	}

	return aliases
}

// Komutun başındaki FOO=bar gibi ortam değişkeni tanımlamalarını temizler ve ilk komutu döner
func extractCommandToken(rawLine string) string {
	fields := strings.Fields(rawLine)
	for _, field := range fields {
		// FOO=bar şeklinde geçici env atamasıysa sıradaki argümana geç
		if strings.Contains(field, "=") && !strings.HasPrefix(field, "=") {
			continue
		}
		return field
	}
	return ""
}

// Komutu çalıştırmadan geçerli bir sistem komutu / alias olup olmadığını kontrol eder
func isValidCommand(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return true
	}

	// Eğer tüm satır geldiyse ilk komut kelimesini ayıkla
	if strings.ContainsAny(command, " \t") {
		command = extractCommandToken(command)
		if command == "" {
			return true
		}
	} else if strings.Contains(command, "=") && !strings.HasPrefix(command, "=") {
		// Tek başına VAR=deger atamasıysa geçerli kabuk ifadesidir
		return true
	}

	if isStringInArray(command, aliases) {
		return true
	}

	if shellBuiltins[command] {
		return true
	}

	// Dışarıdan güvensiz ve yavaş 'which' / 'bash -c' çalıştırmak yerine doğrudan PATH kontrolü
	_, err := exec.LookPath(command)
	return err == nil
}

func extractSecretPassword(input string) (string, error) {
	// Zsh extended_history formatı (: 1689951023:0;komut)
	if strings.HasPrefix(input, ":") && strings.Contains(input, ";") {
		password := strings.SplitN(input, ";", 2)[1]
		token := extractCommandToken(password)
		if token == "" {
			return "", fmt.Errorf("no password found")
		}
		return token, nil
	}

	// Standart zsh history satırı
	token := extractCommandToken(input)
	if token == "" {
		return "", fmt.Errorf("no password found")
	}
	return token, nil
}

func extractSecretPasswordRegex(input string) (string, error) {
	if strings.HasPrefix(input, ":") && strings.Contains(input, ";") {
		password := strings.SplitN(input, ";", 2)[1]
		return password, nil
	}
	return input, nil
}

// Uzun history satırlarında (64KB+) scanner'ın hata vermemesi için buffer boyutunu büyütür
func newHistoryScanner(f *os.File) *bufio.Scanner {
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	return scanner
}

func ProcessZshHistoryFile(historyFile string) {
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening zsh history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := newHistoryScanner(f)
	var fullLine string
	inContinuation := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Önceki satır '\' ile bittiyse devam satırını birleştir
		if inContinuation {
			fullLine += " " + line
		} else {
			fullLine = line
		}

		if strings.HasSuffix(fullLine, "\\") {
			fullLine = strings.TrimSuffix(fullLine, "\\")
			inContinuation = true
			continue
		}
		inContinuation = false

		currentCommand, err := extractSecretPassword(fullLine)
		if err != nil || currentCommand == "" {
			fullLine = ""
			continue
		}

		if !isValidCommand(currentCommand) {
			color.Yellow("Invalid command in %s: %s\n", historyFile, maskIfRedacted(currentCommand))
		}

		fullLine = ""
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading zsh history file %s: %v\n", historyFile, err)
	}
}

func ProcessBashHistoryFile(historyFile string) {
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening bash history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := newHistoryScanner(f)

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		// Boş satırları ve bash history timestamp/yorum satırlarını (#1689951023) atla
		if command == "" || strings.HasPrefix(command, "#") {
			continue
		}

		firstToken := extractCommandToken(command)
		if firstToken == "" {
			continue
		}

		if !isValidCommand(firstToken) {
			color.Red("Invalid command in %s: %s\n", historyFile, maskIfRedacted(command))
		}
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading bash history file %s: %v\n", historyFile, err)
	}
}

func ProcessBashHistoryFileRegex(historyFile string) {
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening bash history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := newHistoryScanner(f)

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		if command == "" || strings.HasPrefix(command, "#") {
			continue
		}
		DetectRegexes(command)
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading bash history file %s: %v\n", historyFile, err)
	}
}

func ProcessZshHistoryFileRegex(historyFile string) {
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening zsh history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := newHistoryScanner(f)
	var currentCommand string
	inContinuation := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if inContinuation {
			currentCommand += " " + line
		} else {
			currentCommand, _ = extractSecretPasswordRegex(line)
		}

		if strings.HasSuffix(currentCommand, "\\") {
			currentCommand = strings.TrimSuffix(currentCommand, "\\")
			inContinuation = true
			continue
		}
		inContinuation = false

		DetectRegexes(currentCommand)
		currentCommand = ""
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading zsh history file %s: %v\n", historyFile, err)
	}
}

// Fish history dosyası (- cmd: komut) formatında tutulur
func extractFishCommand(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "- cmd:") {
		return "", false
	}
	cmd := strings.TrimSpace(strings.TrimPrefix(line, "- cmd:"))
	if cmd == "" {
		return "", false
	}
	return cmd, true
}

func ProcessFishHistoryFile(historyFile string) {
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening fish history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := newHistoryScanner(f)

	for scanner.Scan() {
		command, ok := extractFishCommand(scanner.Text())
		if !ok {
			continue
		}

		firstToken := extractCommandToken(command)
		if firstToken == "" {
			continue
		}

		if !isValidCommand(firstToken) {
			color.Yellow("Invalid command in %s: %s\n", historyFile, maskIfRedacted(command))
		}
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading fish history file %s: %v\n", historyFile, err)
	}
}

func ProcessFishHistoryFileRegex(historyFile string) {
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening fish history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := newHistoryScanner(f)

	for scanner.Scan() {
		command, ok := extractFishCommand(scanner.Text())
		if !ok {
			continue
		}
		DetectRegexes(command)
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading fish history file %s: %v\n", historyFile, err)
	}
}

func maskString(s string) string {
	if len(s) <= 6 {
		return "****"
	}
	return s[:3] + strings.Repeat("*", len(s)-5) + s[len(s)-2:]
}

func maskIfRedacted(input string) string {
	if !RedactOutput {
		return input
	}
	return maskString(input)
}

func DetectRegexes(input string) map[string]bool {
	matchedResults := make(map[string]bool, len(compiledRegexes))

	for label, re := range compiledRegexes {
		match := re.MatchString(input)
		matchedResults[label] = match

		if match {
			color.Green(label)
			if RedactOutput {
				maskedLine := re.ReplaceAllStringFunc(input, maskString)
				color.Red(maskedLine)
			} else {
				color.Red(input)
			}
		}
	}

	return matchedResults
}
