#!/usr/local/bin/python

import json
import click
import urllib.parse
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException

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
def auto_ingress(
  namespace,
  annotation_key,
  additional_ingress_annotations_http,
  additional_ingress_annotations_https,
  kube_config,
):
  click.echo('Loading config...')
  if kube_config:
    config.load_kube_config()
  else:
    config.load_incluster_config()

  additional_ingress_annotations_http = json.loads(additional_ingress_annotations_http)
  additional_ingress_annotations_https = json.loads(additional_ingress_annotations_https)
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
    name = deployment.metadata.name
    namespace = deployment.metadata.namespace
    if deployment.spec.replicas < 1: continue
    if deployment.spec.template.metadata.annotations is None: continue
    if annotation_key not in deployment.spec.template.metadata.annotations: continue
    ingress = deployment.spec.template.metadata.annotations[annotation_key]
    ingress_parsed = urllib.parse.urlparse(ingress)
    ports = {
      port.container_port
      for container in deployment.spec.template.spec.containers
      for port in (container.ports or [])
      if port.name == 'http' and port.protocol == 'TCP'
    }
    if len(ports) > 1:
      click.echo('[%s]: WARNING, multiple ports found, ignoring...' % (name))
      continue
    elif len(ports) == 0:
      click.echo('[%s]: WARNING, no port found with name `http`, ignoring...' % (name))
      continue
    else:
      port = next(iter(ports))
    #
    if event_type in {'ADDED', 'MODIFIED'}:
      click.echo('ensuring %s => %s' % (ingress, str(port)))
      try:
        existing_ingress = networking_v1.read_namespaced_ingress(name, namespace)
      except ApiException as e:
        if e.status != 404:
          raise e
        existing_ingress = None
      #
      if existing_ingress is not None:
        if annotation_key not in existing_ingress.metadata.annotations:
          click.echo('un-automated ingress already exists, ignoring')
          continue
        if existing_ingress.metadata.annotations[annotation_key] == ingress:
          if existing_ingress.spec.rules[0].http.paths[0].backend.service.port.number == port:
            click.echo('automated ingress already exists, ignoring')
            continue
        click.echo('updating %s => %s' % (ingress, str(port)))
      else:
        click.echo('creating %s => %s' % (ingress, str(port)))
      #
      spec = dict(
        ingress_class_name='nginx',
        rules=[
          client.V1IngressRule(
            host=ingress_parsed.hostname,
            http=client.V1HTTPIngressRuleValue(
              paths=[
                client.V1HTTPIngressPath(
                  path=ingress_parsed.path,
                  path_type='ImplementationSpecific',
                  backend=client.V1IngressBackend(
                    service=client.V1IngressServiceBackend(
                      name=name,
                      port=client.V1ServiceBackendPort(
                        number=port,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      )
      annotations = {
        annotation_key: ingress
      }
      if ingress_parsed.scheme == 'http':
        annotations.update(additional_ingress_annotations_http)
      elif ingress_parsed.scheme == 'https':
        spec.update(
          tls=[
            client.V1IngressTLS(
              hosts=[ingress_parsed.hostname],
              secret_name=ingress_parsed.hostname.replace('.', '-')+'-tls',
            ),
          ],
        )
        annotations.update(additional_ingress_annotations_https)
      #
      service = dict(
        namespace=namespace,
        body=client.V1Ingress(
          api_version='networking.k8s.io/v1',
          kind='Ingress',
          metadata=client.V1ObjectMeta(
            name=name,
            annotations=annotations,
          ),
          spec=client.V1IngressSpec(**spec),
        ),
      )
      if existing_ingress is None:
        networking_v1.create_namespaced_ingress(**service)
      else:
        networking_v1.patch_namespaced_ingress(name, namespace, service['body'])
    elif event_type == 'DELETED':
      try:
        existing_ingress = networking_v1.read_namespaced_ingress(name, namespace)
      except ApiException as e:
        if e.status != 404:
          raise e
        click.echo('no existing ingress, ignoring')
        continue
      #
      if annotation_key not in existing_ingress.metadata.annotations:
        click.echo('un-automated ingress, ignoring')
        continue
      #
      try:
        networking_v1.delete_namespaced_ingress(name, namespace)
      except ApiException as e:
        if e.status != 404:
          raise e
      else:
        continue
      #
      click.echo('removed ingress for %s' % (name))

if __name__ == '__main__':
  auto_ingress()
