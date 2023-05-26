from flask import Flask, render_template, url_for, request, session, redirect
from urllib.parse import urlparse
import kubernetes.client, kubernetes.config 
import secrets, random, string, boto3, os

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(16)
domain_name = os.environ.get('DOMAIN_NAME')
ip_address = os.environ.get('IP_ADDRESS')

session_config = boto3.Session(
  aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
  aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'),
  region_name=os.environ.get('AWS_REGION'),
)

def is_valid_url(url):
  """Validate URL."""
  parsed_url = urlparse(url)
  return all([parsed_url.scheme, parsed_url.netloc, parsed_url.path])

def get_hosted_zone_id(domain_name):
  client = session_config.client(service_name='route53')

  try:
    response = client.list_hosted_zones()
    app.logger.info('Successfully listed hosted zones.')
  except Exception as err:
    app.logger.error(f'Could not list hosted zones: {err}')

  try:
    for zone in response['HostedZones']:
      if zone['Name'] == f"{domain_name}.":
        app.logger.info(f"Retrieved hosted zone ID: {zone['Id']}")
        return zone['Id']
  except Exception as err:
    app.logger.error(f"Could not retrieve hosted zone ID: {err}")

def create_a_record(subdomain, ip_address, hosted_zone_id):
  
  client = session_config.client('route53')
  try:
    response = client.change_resource_record_sets(
      HostedZoneId=hosted_zone_id,
      ChangeBatch={
          'Changes': [
              {
                  'Action': 'CREATE',
                  'ResourceRecordSet': {
                      'Name': f"{subdomain}.{domain_name}",
                      'Type': 'A',
                      'TTL': 1,
                      'ResourceRecords': [
                          {
                              'Value': ip_address
                          }
                      ]
                  }
              }
          ]
      }
    )
    app.logger.info(response['ChangeInfo'])

  except Exception as err: 
    app.logger.error(err)

def random_characters(k):
  """Create string of random characters of k length."""
  digits = random.choices(string.digits, k=k)
  letters = random.choices(string.ascii_lowercase, k=k)
  sample = random.sample(digits + letters, k=k)
  return ''.join(sample)

def create_ingress_resource(name: str, url: str):
  """Create an Ingress resource in Kubernetes."""

  kubernetes.config.load_incluster_config()

  with kubernetes.client.ApiClient() as api_client:
    api_instance = kubernetes.client.NetworkingV1Api(api_client=api_client)

    if not os.environ.get('K8S_NAMESPACE'):
      namespace = os.environ.get('K8S_NAMESPACE')
    else:
      namespace = 'zoom-redirect'

    if not os.environ.get('ISSUER_NAME'):
      cluster_issuer = os.environ.get('ISSUER_NAME')
    else: 
      cluster_issuer = 'prod-issuer'

    salt= random_characters(5)

    metadata = kubernetes.client.V1ObjectMeta(
      name=f"{name}-redirect-{salt}",
      labels={"app":"zoom-redirect"},
      annotations={"nginx.ingress.kubernetes.io/rewrite-target":f"{url}", "cert-manager.io/cluster-issuer": f"{cluster_issuer}"}
    )
    port = kubernetes.client.V1ServiceBackendPort(
      name='redirect-port'
    )
    service = kubernetes.client.V1IngressServiceBackend(
      name=f'{name}-svc',
      port=port
    )
    backend = kubernetes.client.V1IngressBackend(
      service=service
    )
    tls = kubernetes.client.V1IngressTLS(
      hosts=[f"{name}.{domain_name}"],
      secret_name=f"{name}-redirect-tls"
    )
    path = kubernetes.client.V1HTTPIngressPath(
      backend=backend,
      path='/',
      path_type='Prefix'
    )
    http = kubernetes.client.V1HTTPIngressRuleValue(
      paths=[path]
    )
    rule = kubernetes.client.V1IngressRule(
      http=http,
      host=f"{name}.{domain_name}"
    )
    spec = kubernetes.client.V1IngressSpec(
      ingress_class_name='nginx',
      rules=[rule],
      tls=[tls],
      default_backend=backend
    )
    ingress = kubernetes.client.V1Ingress(
      metadata=metadata,
      spec=spec
    )

    try:
      api_response = api_instance.create_namespaced_ingress(namespace=namespace, body=ingress)
      app.logger.info(f'Created ingress resource.')
      return api_response
    except Exception as err:
      app.logger.error(f'Could not create Ingress: {err}')

@app.route('/')
def index():
  """Render index page."""
  return render_template('index.html')

@app.route('/create_redirect', methods=['POST'])
def create_redirect():
  """Put it all together."""
  name = request.form.get('name', type=str).lower().strip()
  url = request.form.get('url', type=str)

  session['name'] = name

  if not is_valid_url(url):
    app.logger(f"Invalid URL: {url}")
    error = "Proided URL did not pass URL validation."
    return render_template('failure.html', error=error)

  hosted_zone_id = get_hosted_zone_id(domain_name=domain_name)

  create_a_record(subdomain=name, ip_address=ip_address, hosted_zone_id=hosted_zone_id)
  create_ingress_resource(name=name, url=url)

  return redirect(url_for('success'))

@app.route('/success')
def success():
  """Render success page."""
  name = session.get('name')
  complete_url = f"{name}.{domain_name}"
  return render_template('success.html', complete_url=complete_url)

if __name__ == "__main__":
  app.run()