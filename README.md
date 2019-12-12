# Bitgrit auth API

To build api image run this command in the `auth-microservice` folder:
```
docker build . -t gcr.io/<project-id>/<image-name>:<image-tag>
```

After creating and pushing docker image, you need to deploy API server to the Kubernetes cluster.
First of all, you need to have GCP service account in the manifests folder with `cloudsql-gcp-sa.json` name.
Also verify gcp project name and cloud sql instance name in manifests/overlays/<env>/custom-env.yaml
After that, in manifests/overlays/<env> folder run this command:

```
kustomize build | kubectl create -f -
```

Sample curl command for register api
```
curl -H "Content-Type: application/json" --data '{"email":"abc@gmail.com","password":"pwd"}' http://<ingress controller ip>/auth/register
```

To run the app locally, run below in auth-mcroservice folder
```
export PYTHONPATH=.
export FLASK_APP=main.py
flask db init
flask db migrate
flask db upgrade
flask run
```
