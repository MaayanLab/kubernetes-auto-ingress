#!/usr/local/bin/python

import json
import click
import urllib.parse
import traceback
from kubernetes import client, config, watch
from kubernetes.client.exceptions import ApiException

class MoreThanOneException(Exception):
  def __init__(self) -> None:
    super().__init__("Expected one, got more than one")

def one(it):
  first = next(iter(it))
  try:
    next(iter(it))
  except StopIteration:
    return first
  else:
    raise MoreThanOneException()

def one_or_none(it):
  try:
    return one(it)
  except StopIteration:
    return None
  except MoreThanOneException:
    return None

def endless_watch(*args):
  w = watch.Watch()
  s = iter(w.stream(*args))
  v = None
  while True:
    try:
      event = next(s)
      v = event['object'].metadata.resource_version
      yield event
    except StopIteration:
      s = iter(w.stream(*args, resource_version=v))

def upsert_managed_service(*, deployment: client.V1Deployment, core_v1: client.CoreV1Api, annotation_key: str, ingress_url: str, dry_run: bool):
  service_update_required = False
  try:
    service = core_v1.read_namespaced_service(deployment.metadata.name, deployment.metadata.namespace)
    service_create_required = False
  except ApiException as e:
    if e.status != 404:
      click.echo(e.status)
      raise e
    service_create_required = True
    service = client.V1Service(
      api_version='v1',
      kind='Service',
      metadata=client.V1ObjectMeta(
        name=deployment.metadata.name,
        namespace=deployment.metadata.namespace,
        annotations={annotation_key: ''}
      ),
      spec=client.V1ServiceSpec(
        type='ClusterIP',
        ports=[
          client.V1ServicePort(
            name='http',
            port=80,
            protocol='TCP',
            target_port=None,
          ),
        ],
        selector=deployment.spec.selector.match_labels,
      ),
    )
  if annotation_key not in service.metadata.annotations:
    click.echo(f"found un-managed service/{service.metadata.name} -n {service.metadata.namespace}")
    return service
  # update ingress_url if it changed
  if service.metadata.annotations[annotation_key] != ingress_url:
    service_update_required = True
    service.metadata.annotations[annotation_key] = ingress_url
  # ensure port is up to date
  port = one_or_none(
    port.container_port
    for container in deployment.spec.template.spec.containers
    if container.ports
    for port in container.ports
    if port.name == 'http' and port.protocol == 'TCP'
  ) or one_or_none( # fallback criterion -- only one TCP port there
    port.container_port
    for container in deployment.spec.template.spec.containers
    if container.ports
    for port in container.ports
    if port.protocol == 'TCP'
  )
  assert port is not None
  if service.spec.ports[0].target_port != port:
    service_update_required = True
    service.spec.ports[0].target_port = port
  # apply changes as required
  if service_create_required:
    if not dry_run:
      core_v1.create_namespaced_service(service.metadata.namespace, service)
    click.echo(f"created service/{service.metadata.name} -n {service.metadata.namespace}")
  elif service_update_required:
    if not dry_run:
      core_v1.patch_namespaced_service(service.metadata.name, service.metadata.namespace, service)
    click.echo(f"patched service/{service.metadata.name} -n {service.metadata.namespace}")
  return service

def delete_managed_service(*, deployment: client.V1Deployment, core_v1: client.CoreV1Api, annotation_key: str, dry_run: bool):
  try:
    service = core_v1.read_namespaced_service(deployment.metadata.name, deployment.metadata.namespace)
  except ApiException as e:
    if e.status != 404:
      raise e
    return
  #
  if annotation_key not in service.metadata.annotations:
    click.echo(f"ignoring un-managed service/{service.metadata.name} -n {service.metadata.namespace}")
    return
  #
  try:
    if not dry_run:
      core_v1.delete_namespaced_service(service.metadata.name, service.metadata.namespace)
    click.echo(f"deleted service/{service.metadata.name} -n {service.metadata.namespace}")
  except ApiException as e:
    if e.status != 404:
      raise e

def upsert_managed_ingress(deployment: client.V1Deployment, service: client.V1Service, networking_v1: client.NetworkingV1Api, annotation_key: str, ingress_url: str, ingress_url_parsed: urllib.parse.ParseResult, ingress_class_name: str, ingress_create_tls: bool, additional_ingress_annotations_http: dict, additional_ingress_annotations_https: dict, dry_run: bool):
  ingress_update_required = False
  try:
    ingress = networking_v1.read_namespaced_ingress(deployment.metadata.name, deployment.metadata.namespace)
    ingress_create_required = False
  except ApiException as e:
    if e.status != 404:
      raise e
    ingress_create_required = True
    ingress = client.V1Ingress(
      api_version='networking.k8s.io/v1',
      kind='Ingress',
      metadata=client.V1ObjectMeta(
        name=deployment.metadata.name,
        namespace=deployment.metadata.namespace,
        annotations={annotation_key: ''},
      ),
      spec=client.V1IngressSpec(
        ingress_class_name=ingress_class_name,
        rules=[
          client.V1IngressRule(
            host=ingress_url_parsed.hostname,
            http=client.V1HTTPIngressRuleValue(
              paths=[
                client.V1HTTPIngressPath(
                  path_type='ImplementationSpecific',
                  backend=client.V1IngressBackend(
                    service=client.V1IngressServiceBackend(
                      name=service.metadata.name,
                      port=client.V1ServiceBackendPort(
                        number=None,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    )
  if annotation_key not in ingress.metadata.annotations or not ingress.metadata.annotations[annotation_key].endswith(ingress.spec.rules[0].http.paths[0].path or ''):
    click.echo(f"found un-managed ingress/{ingress.metadata.name} -n {ingress.metadata.namespace}")
    return ingress
  # update ingress_url if it changed
  if ingress.metadata.annotations[annotation_key] != ingress_url:
    ingress_update_required = True
    # update the annotation so we know we're in sync
    ingress.metadata.annotations[annotation_key] = ingress_url
    # update the actual path
    ingress.spec.rules[0].http.paths[0].path = ingress_url_parsed.path
    # update the scheme
    if ingress_url_parsed.scheme == 'http':
      # swap http=>https
      for k in additional_ingress_annotations_https:
        if k in ingress.metadata.annotations:
          del ingress.metadata.annotations[k]
      for k, v in additional_ingress_annotations_http.items():
        ingress.metadata.annotations[k] = v
      # no tls
      ingress.spec.tls = None
    elif ingress_url_parsed.scheme == 'https':
      # swap http=>https
      for k in additional_ingress_annotations_http:
        if k in ingress.metadata.annotations:
          del ingress.metadata.annotations[k]
      for k, v in additional_ingress_annotations_https.items():
        ingress.metadata.annotations[k] = v
      # add tls
      if ingress_create_tls:
        ingress.spec.tls = [
          client.V1IngressTLS(
            hosts=[ingress_url_parsed.hostname],
            secret_name=ingress_url_parsed.hostname.replace('.', '-')+'-tls',
          ),
        ]
      else:
        ingress.spec.tls = None
  # any ingress-related annotations in the deployment not reflected in the ingress?
  deployment_nginx_annotations = {
    (k, v) for k, v in deployment.metadata.annotations.items()
    if k.startswith('nginx.ingress.kubernetes.io/') or k.startswith('traefik.ingress.kubernetes.io/')
  }
  ingress_nginx_annotations = {
    (k, v) for k, v in ingress.metadata.annotations.items()
    if k.startswith('nginx.ingress.kubernetes.io/') or k.startswith('traefik.ingress.kubernetes.io/')
  }
  if deployment_nginx_annotations ^ ingress_nginx_annotations:
    ingress_update_required = True
    for k in {k for k, _ in deployment_nginx_annotations ^ ingress_nginx_annotations}:
      if k in deployment.metadata.annotations:
        ingress.metadata.annotations[k] = deployment.metadata.annotations[k]
      elif ingress_url_parsed.scheme == 'http' and k in additional_ingress_annotations_http:
        ingress.metadata.annotations[k] = additional_ingress_annotations_http[k]
      elif ingress_url_parsed.scheme == 'https' and k in additional_ingress_annotations_https:
        ingress.metadata.annotations[k] = additional_ingress_annotations_https[k]
      else:
        ingress.metadata.annotations[k] = None
  # add server-aliases to tls hosts (will only result in a change if annotations changed or ingress_url changed)
  if ingress.spec.tls and ingress.metadata.annotations.get('nginx.ingress.kubernetes.io/server-alias'):
    # we add the unique comma separated aliases except the potentially duplicated primary hostname which is already there
    server_aliases = set(ingress.metadata.annotations['nginx.ingress.kubernetes.io/server-alias'].split(',')) - {ingress_url_parsed.hostname}
    if ingress_create_tls:
      ingress.spec.tls[0].hosts += list(server_aliases)
  # ensure port is up to date
  port = one_or_none(
    service_port.port
    for service_port in service.spec.ports
    if service_port.name == 'http' and service_port.protocol == 'TCP'
  ) or one_or_none( # fallback criterion: only one port there
    service_port.port
    for service_port in service.spec.ports
    if service_port.protocol == 'TCP'
  )
  if ingress.spec.rules[0].http.paths[0].backend.service.port.number != port:
    ingress_update_required = True
    ingress.spec.rules[0].http.paths[0].backend.service.port.number = port
  # apply changes as required
  if ingress_create_required:
    if not dry_run:
      networking_v1.create_namespaced_ingress(deployment.metadata.namespace, ingress)
    click.echo(f"created ingress/{ingress.metadata.name} -n {ingress.metadata.namespace}")
  elif ingress_update_required:
    if not dry_run:
      networking_v1.patch_namespaced_ingress(deployment.metadata.name, deployment.metadata.namespace, ingress)
    click.echo(f"patched ingress/{ingress.metadata.name} -n {ingress.metadata.namespace}")
  return ingress

def delete_managed_ingress(*, deployment: client.V1Deployment, networking_v1: client.NetworkingV1Api, annotation_key: str, ingress_url: str, ingress_url_parsed: urllib.parse.ParseResult, dry_run: bool):
  try:
    ingress = networking_v1.read_namespaced_ingress(deployment.metadata.name, deployment.metadata.namespace)
  except ApiException as e:
    if e.status != 404:
      raise e
    return
  #
  if annotation_key not in ingress.metadata.annotations or not ingress.metadata.annotations[annotation_key].endswith(ingress.spec.rules[0].http.paths[0].path or ''):
    click.echo(f"ignoring un-managed ingress/{ingress.metadata.name} -n {ingress.metadata.namespace}")
    return
  #
  try:
    if not dry_run:
      networking_v1.delete_namespaced_ingress(ingress.metadata.name, ingress.metadata.namespace)
    click.echo(f"deleted ingress/{ingress.metadata.name} -n {ingress.metadata.namespace}")
  except ApiException as e:
    if e.status != 404:
      raise e

@click.command(
  help='Automatically watch and register ingresses'
)
@click.option(
  '--namespace',
  envvar='NAMESPACE',
  default='default',
  help='Kubernetes namespace to watch / register ingresses. * for all namespaces',
  show_default=True,
)
@click.option(
  '--annotation-key',
  envvar='ANNOTATION_KEY',
  default='maayanlab.cloud/ingress',
  help='Annotation key to watch for',
  show_default=True,
)
@click.option(
  '--ingress-class-name',
  envvar='INGRESS_CLASS_NAME',
  default='nginx',
  help='Kubernetes ingress class name',
  show_default=True,
)
@click.option(
  '--ingress-create-tls',
  envvar='INGRESS_CREATE_TLS',
  default=False,
  help='Create kubernetes ingress tls/secret (cert-manager)',
  is_flag=True,
)
@click.option(
  '--additional-ingress-annotations-http',
  envvar='ADDITIONAL_INGRESS_ANNOTATIONS_HTTP',
  default='{ "nginx.ingress.kubernetes.io/ssl-redirect": "false" }',
  help='Additional ingress annotations (JSON)',
  show_default=True,
)
@click.option(
  '--additional-ingress-annotations-https',
  envvar='ADDITIONAL_INGRESS_ANNOTATIONS_HTTPS',
  default='{ "cert-manager.io/cluster-issuer": "letsencrypt-prod", "kubernetes.io/tls-acme": "true" }',
  help='Additional ingress annotations (JSON)',
  show_default=True,
)
@click.option(
  '--kube-config',
  envvar='KUBECONFIG',
  help='Use kubeconfig instead of incluster config',
  is_flag=True,
)
@click.option(
  '--dry-run',
  envvar='DRY_RUN',
  help='Dont do anything, just show what would be done',
  is_flag=True,
)
def auto_ingress(
  namespace,
  annotation_key,
  ingress_class_name,
  ingress_create_tls,
  additional_ingress_annotations_http,
  additional_ingress_annotations_https,
  kube_config,
  dry_run,
):
  click.echo('Loading config...')
  if kube_config:
    config.load_kube_config()
  else:
    try:
      config.load_incluster_config()
    except:
      config.load_kube_config()

  additional_ingress_annotations_http = json.loads(additional_ingress_annotations_http)
  additional_ingress_annotations_https = json.loads(additional_ingress_annotations_https)
  core_v1 = client.CoreV1Api()
  apps_v1 = client.AppsV1Api()
  networking_v1 = client.NetworkingV1Api()

  click.echo('Starting..')
  if namespace == '*':
    event_stream = endless_watch(apps_v1.list_deployment_for_all_namespaces)
  else:
    event_stream = endless_watch(apps_v1.list_namespaced_deployment, namespace)
  #
  for event in event_stream:
    event_type = event['type']
    deployment = event['object']
    try:
      try:
        ingress_url = one(filter(None, {
          deployment.metadata.annotations and deployment.metadata.annotations.get(annotation_key),
          deployment.spec.template.metadata.annotations and deployment.spec.template.metadata.annotations.get(annotation_key),
        }))
      except StopIteration:
        continue
      if deployment.spec.template.metadata.annotations and deployment.spec.template.metadata.annotations.get(annotation_key):
        click.echo(f"WARNING {deployment.metadata.namespace}/{deployment.metadata.name} using legacy annotation in pod template")
      ingress_url_parsed = urllib.parse.urlparse(ingress_url)
      #
      if event_type in {'ADDED', 'MODIFIED'} and deployment.spec.replicas >= 1:
        service = upsert_managed_service(
          deployment=deployment,
          core_v1=core_v1,
          annotation_key=annotation_key,
          ingress_url=ingress_url,
          dry_run=dry_run,
        )
        upsert_managed_ingress(
          deployment=deployment,
          service=service,
          networking_v1=networking_v1,
          annotation_key=annotation_key,
          ingress_url=ingress_url,
          ingress_url_parsed=ingress_url_parsed,
          ingress_class_name=ingress_class_name,
          ingress_create_tls=ingress_create_tls,
          additional_ingress_annotations_http=additional_ingress_annotations_http,
          additional_ingress_annotations_https=additional_ingress_annotations_https,
          dry_run=dry_run,
        )
      elif event_type == 'DELETED' or deployment.spec.replicas < 1:
        delete_managed_ingress(
          deployment=deployment,
          networking_v1=networking_v1,
          annotation_key=annotation_key,
          ingress_url=ingress_url,
          ingress_url_parsed=ingress_url_parsed,
          dry_run=dry_run,
        )
        delete_managed_service(
          deployment=deployment,
          core_v1=core_v1,
          annotation_key=annotation_key,
          dry_run=dry_run,
        )
      else:
        click.echo(f"Ignored {event_type} {deployment.spec.replicas}")
    except:
      click.echo(f"error processing {event_type} {deployment.metadata.namespace}/{deployment.metadata.name}\n{traceback.format_exc()}")

if __name__ == '__main__':
  auto_ingress()
