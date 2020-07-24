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
  help='Kubernetes namespace to watch / register ingresses',
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
  '--additional-ingress-annotations',
  envvar='ADDITIONAL_INGRESS_ANNOTATIONS',
  default='{ "cert-manager.io/issuer": "letsencrypt-prod", "kubernetes.io/tls-acme": "true" }',
  help='Annotation key to watch for',
  show_default=True,
)
@click.option(
  '--kube-config',
  envvar='ADDITIONAL_INGRESS_ANNOTATIONS',
  help='Annotation key to watch for',
  is_flag=True,
)
def auto_ingress(
  namespace,
  annotation_key,
  additional_ingress_annotations,
  kube_config,
):
  click.echo('Loading config...')
  if kube_config:
    config.load_kube_config()
  else:
    config.load_incluster_config()

  additional_ingress_annotations = json.loads(additional_ingress_annotations)
  apps_v1 = client.AppsV1Api()
  networking_v1_beta1 = client.NetworkingV1beta1Api()

  click.echo('Starting..')
  for event in endless_watch(apps_v1.list_namespaced_deployment, namespace):
    event_type = event['type']
    deployment = event['object']
    name = deployment.metadata.name
    if annotation_key in deployment.spec.template.metadata.annotations:
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
          existing_ingress = networking_v1_beta1.read_namespaced_ingress(name, namespace)
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
            click.echo('automated ingress already exists, ignoring')
            continue
          click.echo('updating %s => %s' % (ingress, str(port)))
        else:
          click.echo('creating %s => %s' % (ingress, str(port)))
        #
        spec = dict(
          rules=[
            client.NetworkingV1beta1IngressRule(
              host=ingress_parsed.hostname,
              http=client.NetworkingV1beta1HTTPIngressRuleValue(
                paths=[
                  client.NetworkingV1beta1HTTPIngressPath(
                    path=ingress_parsed.path,
                    backend=client.NetworkingV1beta1IngressBackend(
                      service_name=name,
                      service_port=port,
                    ),
                  ),
                ],
              ),
            ),
          ],
        )
        if ingress_parsed.scheme == 'https':
          spec.update(
            tls=[
              client.NetworkingV1beta1IngressTLS(
                hosts=[ingress_parsed.hostname],
                secret_name=ingress_parsed.hostname.replace('.', '-')+'-tls',
              ),
            ],
          )
        service = dict(
          namespace=namespace,
          body=client.NetworkingV1beta1Ingress(
            api_version='networking.k8s.io/v1beta1',
            kind='Ingress',
            metadata=client.V1ObjectMeta(
              name=name,
              annotations=dict(additional_ingress_annotations, **{ annotation_key: ingress }),
            ),
            spec=client.NetworkingV1beta1IngressSpec(**spec),
          ),
        )
        if existing_ingress is None:
          networking_v1_beta1.create_namespaced_ingress(**service)
        else:
          networking_v1_beta1.patch_namespaced_ingress(name, namespace, service['body'])
      elif event_type == 'DELETED':
        try:
          existing_ingress = networking_v1_beta1.read_namespaced_ingress(name, namespace)
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
          networking_v1_beta1.delete_namespaced_ingress(name, namespace)
        except ApiException as e:
          if e.status != 404:
            raise e
        else:
          continue
        #
        click.echo('removed ingress for %s' % (name))

if __name__ == '__main__':
  auto_ingress()
