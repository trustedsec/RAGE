# RAGE Taxonomy Corpus

The complete corpus behind the **Relational Attack Graph Exchange** — the provider-independent
node & edge vocabularies, the concrete **AWS / GCP / Azure** resource mappings, the collection
recipes that produce them, and the derivation rules that infer edges.

This document is **generated from RAGE's own registries** (`vocab/`, `rules/`, `providers/`) —
RAGE is the source of truth. Regenerate with `python3 tools/gen_taxonomy.py`; do not hand-edit.

Both registries are **open**: an unknown `node_type` or edge `type` is legal — map it to the
nearest generic type and keep the native string verbatim. Everything below is the grounded
baseline every conforming producer and consumer can rely on.

**At a glance:** 10 node classes · 105 generic node types · 80 edge types in 9 categories · 106 AWS + 53 GCP + 60 Azure concrete resource types · 22 fact/relationship recipes · 80 derivation rules · 1049 exposure sites.

## Contents
1. [Node taxonomy](#1-node-taxonomy)
2. [Provider resource corpus & collection recipes](#2-provider-resource-corpus--collection-recipes)
3. [Generic type → concrete resources](#3-generic-type--concrete-resources)
4. [Service coverage](#4-service-coverage)
5. [Edge taxonomy & derivation rules](#5-edge-taxonomy--derivation-rules)
6. [Exposure DB](#6-exposure-db)

---

## 1. Node taxonomy

A concrete resource carries **both** a generic `node_type` (its security role) and its verbatim
`provider_type`. Rules prefer the generic type. `vocab/node-types.json` is the registry.

### 1.1 Classes

| Class | Description |
|---|---|
| **Identity** | Any principal that can hold permissions or be authenticated as. |
| **AdministrativeBoundary** | Containers that scope permissions, policy inheritance, and control. |
| **Compute** | Resources that execute attacker-influenceable code and usually run AS an identity. |
| **Storage** | Durable data-at-rest stores — objects, files, blocks, snapshots, backups, and artifact/image repositories an attacker reads, writes, or exfiltrates. |
| **Data** | Structured data services — relational/NoSQL databases, warehouses, caches, search and analytics stores holding queryable data. |
| **Messaging** | Integration primitives that can trigger execution or carry credentials. |
| **Secret** | Credential and cryptographic material — terminal targets and pivots. |
| **Network** | Connectivity and reachability primitives (networks, subnets, firewalls, routes, endpoints) that gate whether one resource can reach another. |
| **Policy** | Authorization & governance artifacts. Nodes so their mutation is an edge target. |
| **ManagementService** | Control-plane & security services whose abuse enables execution, persistence, or evasion. |

### 1.2 Generic node types

#### Identity (13)

| Type | Description |
|---|---|
| `HumanIdentity` | Interactive user backed by a human (console/SSO login). |
| `MachineIdentity` | Non-human principal an attacker can assume/impersonate (role/SA/MI). |
| `WorkloadIdentity` | Identity bound to a running workload via platform attestation (IRSA, WI, pod identity). |
| `ServiceIdentity` | Identity a managed service runs as / on behalf of. |
| `ApplicationIdentity` | Registered app/client with its own credentials & grants (Entra app, OAuth client). |
| `FederatedIdentity` | Identity asserted from an external IdP via trust/federation. |
| `ExternalIdentity` | Principal from another tenant/account/org or third party. |
| `AnonymousIdentity` | Unauthenticated / public principal (allUsers, *). |
| `Group` | Membership container that grants inherited permissions. |
| `Role` | Assumable/assignable bundle of permissions (distinct from the principal that holds it). |
| `ServiceAccount` | GCP-style SA; also a MachineIdentity but modeled distinctly for impersonation semantics. |
| `ManagedIdentity` | Azure MI (system/user-assigned) bound to resources. |
| `GenericIdentity` |  |

#### AdministrativeBoundary (11)

| Type | Description |
|---|---|
| `CloudProvider` | Root of a provider's presence. |
| `Organization` | Top control boundary (AWS Org, GCP Org, Entra tenant root). |
| `Tenant` | Azure Entra directory / identity boundary. |
| `ManagementGroup` | Azure MG; hierarchical policy scope. |
| `Folder` | GCP folder / AWS OU. |
| `Account` | AWS account — hard isolation + billing boundary. |
| `Subscription` | Azure subscription — RBAC + billing boundary. |
| `Project` | GCP project — resource + IAM boundary. |
| `ResourceGroup` | Azure resource group / logical grouping scope. |
| `Namespace` | K8s namespace or logical partition. |
| `GenericBoundary` |  |

#### Compute (13)

| Type | Description |
|---|---|
| `VirtualMachine` | IaaS instance (EC2/VM/GCE). |
| `ServerlessFunction` | FaaS (Lambda/Functions/Cloud Functions/Cloud Run jobs). |
| `Container` | A single container instance. |
| `ContainerService` | Managed container runtime (ECS/ACI/Cloud Run service). |
| `ContainerCluster` | Cluster control plane (ECS cluster/AKS/GKE/EKS). |
| `ContainerTask` | Task/pod definition that runs as an identity. |
| `KubernetesCluster` | K8s API server + RBAC domain. |
| `KubernetesWorkload` | Deployment/Pod/Job bound to a service account. |
| `BuildWorker` | CI/CD build agent (CodeBuild/Pipelines/Cloud Build). |
| `BatchJob` | Batch/job execution unit. |
| `Notebook` | Managed notebook (SageMaker/AzureML/Vertex). |
| `ApplicationPlatform` | PaaS app host (App Runner/App Service/App Engine). |
| `GenericCompute` |  |

#### Storage (8)

| Type | Description |
|---|---|
| `ObjectStorage` | S3/Blob/GCS bucket. |
| `FileStorage` | EFS/Azure Files/Filestore. |
| `BlockStorage` | EBS/Managed Disk/Persistent Disk. |
| `Backup` | Backup vault/set. |
| `Snapshot` | Volume/DB snapshot — often exportable cross-account. |
| `ArtifactRepository` | Package/artifact registry (CodeArtifact/Artifacts/Artifact Registry). |
| `ContainerRegistry` | Image registry (ECR/ACR/Artifact Registry) — code supply chain. |
| `GenericStorage` |  |

#### Data (9)

| Type | Description |
|---|---|
| `RelationalDatabase` | RDS/SQL DB/Cloud SQL. |
| `NoSQLDatabase` | DynamoDB/Cosmos/Firestore/Bigtable. |
| `DataWarehouse` | Redshift/Synapse/BigQuery. |
| `Cache` | ElastiCache/Redis/Memorystore. |
| `SearchService` | OpenSearch/Cognitive Search. |
| `AnalyticsService` | EMR/Databricks/Dataproc/Glue. |
| `DataLake` | Lake Formation/ADLS/BigLake. |
| `GenericData` |  |
| `MLModel` | A trained ML model artifact (e.g. SageMaker model) — an inference asset and data target. |

#### Messaging (10)

| Type | Description |
|---|---|
| `Queue` | SQS/Service Bus queue/Pub/Sub. |
| `Topic` | SNS/Service Bus topic/Pub/Sub topic. |
| `EventBus` | EventBridge/Event Grid/Eventarc. |
| `EventRule` | Rule mapping events -> targets (trigger creator). |
| `Workflow` | Step Functions/Logic Apps/Workflows. |
| `Scheduler` | EventBridge Scheduler/Automation/Cloud Scheduler. |
| `Webhook` | Inbound HTTP trigger. |
| `API` | Service API surface. |
| `APIGateway` | API GW/APIM/API Gateway — front door + authz. |
| `GenericMessaging` |  |

#### Secret (12)

| Type | Description |
|---|---|
| `Secret` | Secret store entry (Secrets Manager/Key Vault secret/Secret Manager). |
| `Credential` | Generic credential blob. |
| `APIKey` | Long-lived API key. |
| `AccessKey` | IAM access key / SP client secret. |
| `Certificate` | X.509 cert + private key. |
| `SSHKey` | SSH keypair. |
| `EncryptionKey` | KMS/Key Vault/Cloud KMS symmetric or asymmetric key. |
| `SigningKey` | Key usable to sign tokens/artifacts. |
| `Token` | OAuth/OIDC/session token. |
| `Password` | Password credential. |
| `ConnectionString` | Embedded credential (DB/queue conn string). |
| `GenericSecret` |  |

#### Network (15)

| Type | Description |
|---|---|
| `VirtualNetwork` | VPC/VNet/VPC network. |
| `Subnet` | Subnet. |
| `SecurityGroup` | Instance-level stateful filter. |
| `Firewall` | Network/subnet firewall or NSG. |
| `Route` | Route table entry. |
| `LoadBalancer` | ALB/NLB/App GW/LB. |
| `PrivateEndpoint` | PrivateLink/Private Endpoint/PSC. |
| `PublicEndpoint` | Public IP/DNS/ingress surface. |
| `VPN` | VPN gateway. |
| `Peering` | VPC/VNet peering. |
| `TransitGateway` | TGW/vWAN/Network Connectivity Center hub. |
| `DNS` | Managed DNS zone/record. |
| `NAT` | NAT gateway. |
| `NetworkInterface` | ENI/NIC — binds a workload to a network position. |
| `GenericNetwork` |  |

#### Policy (8)

| Type | Description |
|---|---|
| `IAMPolicy` | Identity-attached permission policy. |
| `ResourcePolicy` | Resource-attached policy (bucket policy, KV access policy, IAM allow on resource). |
| `TrustPolicy` | Who may assume/impersonate a role/SA. |
| `PermissionBoundary` | AWS permission boundary cap. |
| `OrganizationPolicy` | GCP org policy / governance constraint. |
| `ServiceControlPolicy` | AWS SCP guardrail. |
| `ConditionalPolicy` | Condition-bearing binding / Conditional Access / deny assignment. |
| `GenericPolicy` |  |

#### ManagementService (6)

| Type | Description |
|---|---|
| `LoggingService` | CloudTrail/Monitor/Cloud Logging — tampering target. |
| `SecurityService` | GuardDuty/Defender/SCC. |
| `ConfigurationService` | Config/Policy/asset inventory. |
| `AutomationService` | SSM Automation/Azure Automation/Cloud Deploy. |
| `RemoteManagementService` | SSM/Run Command/OS Login — direct command exec on hosts. |
| `GenericManagement` |  |

---

## 2. Provider resource corpus & collection recipes

Every native resource type each provider defines, the RAGE node type it maps to, and the recipe a
conforming **RAGE Collector** uses to enumerate it. `providers/{aws,gcp,azure}.json` are the registries.

### 2.1 AWS (106 resource types)

| Resource type | Node type | Scope | Enumerate | Required permissions |
|---|---|---|---|---|
| `aws:accessanalyzer:analyzer` | `SecurityService` | regional | `access-analyzer:ListAnalyzers` | `access-analyzer:ListAnalyzers` |
| `aws:account:region` | `Account` | global | `account:ListRegions` | `account:ListRegions` |
| `aws:acm:certificate` | `Certificate` | regional | `acm:ListCertificates` | `acm:ListCertificates` |
| `aws:acmpca:certificate-authority` | `SigningKey` | regional | `acm-pca:ListCertificateAuthorities` | `acm-pca:ListCertificateAuthorities` |
| `aws:amplify:app` | `ApplicationPlatform` | regional | `amplify:ListApps` | `amplify:ListApps` |
| `aws:apigateway:rest-api` | `APIGateway` | regional | `apigateway:GET` | `apigateway:GET` |
| `aws:appflow:flow` | `Workflow` | regional | `appflow:ListFlows` | `appflow:ListFlows` |
| `aws:appmesh:mesh` | `GenericNetwork` | regional | `appmesh:ListMeshes` | `appmesh:ListMeshes` |
| `aws:apprunner:service` | `ApplicationPlatform` | regional | `apprunner:ListServices` | `apprunner:ListServices` |
| `aws:athena:workgroup` | `AnalyticsService` | regional | `athena:ListWorkGroups` | `athena:ListWorkGroups` |
| `aws:autoscaling:auto-scaling-group` | `GenericCompute` | regional | `autoscaling:DescribeAutoScalingGroups` | `autoscaling:DescribeAutoScalingGroups` |
| `aws:backup:vault` | `Backup` | regional | `backup:ListBackupVaults` | `backup:ListBackupVaults` |
| `aws:batch:job-queue` | `BatchJob` | regional | `batch:DescribeJobQueues` | `batch:DescribeJobQueues` |
| `aws:beanstalk:environment` | `ApplicationPlatform` | regional | `beanstalk:DescribeEnvironments` | `elasticbeanstalk:DescribeEnvironments` |
| `aws:bedrock:custom_model` | `MLModel` | regional | `bedrock:ListCustomModels` | `bedrock:ListCustomModels` |
| `aws:cloudformation:stack` | `AutomationService` | regional | `cloudformation:DescribeStacks` | `cloudformation:DescribeStacks` |
| `aws:cloudfront:distribution` | `LoadBalancer` | global | `cloudfront:ListDistributions` | `cloudfront:ListDistributions` |
| `aws:cloudhsm:cluster` | `EncryptionKey` | regional | `cloudhsm:DescribeClusters` | `cloudhsm:DescribeClusters` |
| `aws:cloudtrail:trail` | `LoggingService` | regional | `cloudtrail:DescribeTrails` | `cloudtrail:DescribeTrails` |
| `aws:cloudwatch:log_group` | `LoggingService` | regional | `cloudwatch:DescribeLogGroups` | `logs:DescribeLogGroups` |
| `aws:codeartifact:repository` | `ArtifactRepository` | regional | `codeartifact:ListRepositories` | `codeartifact:ListRepositories` |
| `aws:codebuild:project` | `BuildWorker` | regional | `codebuild:ListProjects` +1 detail | `codebuild:ListProjects`, `codebuild:BatchGetProjects` |
| `aws:codecommit:repository` | `ArtifactRepository` | regional | `codecommit:ListRepositories` | `codecommit:ListRepositories` |
| `aws:codedeploy:application` | `AutomationService` | regional | `codedeploy:ListApplications` | `codedeploy:ListApplications` |
| `aws:codepipeline:pipeline` | `Workflow` | regional | `codepipeline:ListPipelines` | `codepipeline:ListPipelines` |
| `aws:cognito:user_pool` | `FederatedIdentity` | regional | `cognito:ListUserPools` | `cognito-idp:ListUserPools` |
| `aws:config:config-rule` | `ConfigurationService` | regional | `config:DescribeConfigRules` | `config:DescribeConfigRules` |
| `aws:controltower:landing_zone` | `GenericManagement` | regional | `controltower:ListLandingZones` | `controltower:ListLandingZones` |
| `aws:datapipeline:pipeline` | `Workflow` | regional | `datapipeline:ListPipelines` | `datapipeline:ListPipelines` |
| `aws:detective:graph` | `SecurityService` | regional | `detective:ListGraphs` | `detective:ListGraphs` |
| `aws:directconnect:connection` | `VPN` | regional | `directconnect:DescribeConnections` | `directconnect:DescribeConnections` |
| `aws:documentdb:db_cluster` | `NoSQLDatabase` | regional | `documentdb:DescribeDBClusters` | `rds:DescribeDBClusters` |
| `aws:ds:directory` | `FederatedIdentity` | regional | `ds:DescribeDirectories` | `ds:DescribeDirectories` |
| `aws:dynamodb:table` | `NoSQLDatabase` | regional | `dynamodb:ListTables` | `dynamodb:ListTables` |
| `aws:ebs:snapshot` | `Snapshot` | regional | `ebs:DescribeSnapshots` | `ec2:DescribeSnapshots` |
| `aws:ec2:instance` | `VirtualMachine` | regional | `ec2:DescribeInstances` | `ec2:DescribeInstances` |
| `aws:ec2:network-interface` | `NetworkInterface` | region | `ec2:DescribeNetworkInterfaces` | `ec2:DescribeNetworkInterfaces` |
| `aws:ec2:route-table` | `Route` | region | `ec2:DescribeRouteTables` | `ec2:DescribeRouteTables` |
| `aws:ec2:security-group` | `SecurityGroup` | region | `ec2:DescribeSecurityGroups` | `ec2:DescribeSecurityGroups` |
| `aws:ec2:subnet` | `Subnet` | region | `ec2:DescribeSubnets` | `ec2:DescribeSubnets` |
| `aws:ec2:vpc-endpoint` | `PrivateEndpoint` | region | `ec2:DescribeVpcEndpoints` | `ec2:DescribeVpcEndpoints` |
| `aws:ecr:repository` | `ContainerRegistry` | regional | `ecr:DescribeRepositories` | `ecr:DescribeRepositories` |
| `aws:ecs:cluster` | `ContainerCluster` | regional | `ecs:ListClusters` | `ecs:ListClusters` |
| `aws:efs:filesystem` | `FileStorage` | regional | `elasticfilesystem:DescribeFileSystems` | `elasticfilesystem:DescribeFileSystems` |
| `aws:eks:cluster` | `KubernetesCluster` | regional | `eks:ListClusters` | `eks:ListClusters` |
| `aws:elasticache:cache_cluster` | `Cache` | regional | `elasticache:DescribeCacheClusters` | `elasticache:DescribeCacheClusters` |
| `aws:elb:load_balancer` | `LoadBalancer` | regional | `elasticloadbalancing:DescribeLoadBalancers` | `elasticloadbalancing:DescribeLoadBalancers` |
| `aws:emr:cluster` | `AnalyticsService` | regional | `elasticmapreduce:ListClusters` | `elasticmapreduce:ListClusters` |
| `aws:eventbridge:event_bus` | `EventBus` | regional | `eventbridge:ListEventBuses` | `events:ListEventBuses` |
| `aws:firewallmanager:policy` | `SecurityService` | regional | `firewallmanager:ListPolicies` | `fms:ListPolicies` |
| `aws:fsx:file_system` | `FileStorage` | regional | `fsx:DescribeFileSystems` | `fsx:DescribeFileSystems` |
| `aws:globalaccelerator:accelerator` | `PublicEndpoint` | global | `globalaccelerator:ListAccelerators` | `globalaccelerator:ListAccelerators` |
| `aws:glue:job` | `BatchJob` | regional | `glue:GetJobs` | `glue:GetJobs` |
| `aws:guardduty:detector` | `SecurityService` | regional | `guardduty:ListDetectors` | `guardduty:ListDetectors` |
| `aws:iam:access-key` | `AccessKey` | global | `iam:ListAccessKeys` | `iam:ListAccessKeys` |
| `aws:iam:group` | `Group` | global | `iam:ListGroups` | `iam:ListGroups` |
| `aws:iam:policy` | `IAMPolicy` | global | `iam:ListPolicies` | `iam:ListPolicies` |
| `aws:iam:role` | `Role` | global | `iam:ListRoles` | `iam:ListRoles` |
| `aws:iam:user` | `HumanIdentity` | global | `iam:ListUsers` | `iam:ListUsers` |
| `aws:imagebuilder:image_pipeline` | `BuildWorker` | regional | `imagebuilder:ListImagePipelines` | `imagebuilder:ListImagePipelines` |
| `aws:inspector:finding` | `SecurityService` | regional | `inspector:ListFindings` | `inspector2:ListFindings` |
| `aws:keyspaces:keyspace` | `NoSQLDatabase` | regional | `cassandra:Select` | `cassandra:Select` |
| `aws:kinesis:stream` | `Queue` | regional | `kinesis:ListStreams` | `kinesis:ListStreams` |
| `aws:kms:key` | `EncryptionKey` | regional | `kms:ListKeys` | `kms:ListKeys` |
| `aws:lakeformation:resource` | `DataLake` | regional | `lakeformation:ListResources` | `lakeformation:ListResources` |
| `aws:lambda:function` | `ServerlessFunction` | regional | `lambda:ListFunctions` +2 detail | `lambda:ListFunctions`, `lambda:GetFunction` |
| `aws:lightsail:instance` | `VirtualMachine` | regional | `lightsail:GetInstances` | `lightsail:GetInstances` |
| `aws:macie:classification-job` | `SecurityService` | regional | `macie:ListClassificationJobs` | `macie2:ListClassificationJobs` |
| `aws:memorydb:cluster` | `Cache` | regional | `memorydb:DescribeClusters` | `memorydb:DescribeClusters` |
| `aws:mq:broker` | `Queue` | regional | `mq:ListBrokers` | `mq:ListBrokers` |
| `aws:msk:cluster` | `Queue` | regional | `msk:ListClustersV2` | `kafka:ListClustersV2` |
| `aws:neptune:db_cluster` | `NoSQLDatabase` | regional | `neptune:DescribeDBClusters` | `rds:DescribeDBClusters` |
| `aws:networkfirewall:firewall` | `Firewall` | regional | `network-firewall:ListFirewalls` | `network-firewall:ListFirewalls` |
| `aws:opensearch:domain` | `SearchService` | regional | `es:ListDomainNames` | `es:ListDomainNames` |
| `aws:opsworks:stack` | `AutomationService` | regional | `opsworks:DescribeStacks` | `opsworks:DescribeStacks` |
| `aws:organizations:account` | `Account` | global | `organizations:ListAccounts` | `organizations:ListAccounts` |
| `aws:qldb:ledger` | `GenericData` | regional | `qldb:ListLedgers` | `qldb:ListLedgers` |
| `aws:quicksight:dashboard` | `AnalyticsService` | regional | `quicksight:ListDashboards` | `quicksight:ListDashboards` |
| `aws:ram:resource_share` | `ResourcePolicy` | regional | `ram:GetResourceShares` | `ram:GetResourceShares` |
| `aws:rds:db_instance` | `RelationalDatabase` | regional | `rds:DescribeDBInstances` | `rds:DescribeDBInstances` |
| `aws:redshift:cluster` | `DataWarehouse` | regional | `redshift:DescribeClusters` | `redshift:DescribeClusters` |
| `aws:rolesanywhere:trust-anchor` | `FederatedIdentity` | regional | `rolesanywhere:ListTrustAnchors` | `rolesanywhere:ListTrustAnchors` |
| `aws:route53:hosted_zone` | `DNS` | global | `route53:ListHostedZones` | `route53:ListHostedZones` |
| `aws:s3:bucket` | `ObjectStorage` | global | `s3:ListBuckets` | `s3:ListAllMyBuckets` |
| `aws:sagemaker:model` | `MLModel` | regional | `sagemaker:ListModels` | `sagemaker:ListModels` |
| `aws:sagemaker:notebook-instance` | `Notebook` | regional | `sagemaker:ListNotebookInstances` | `sagemaker:ListNotebookInstances` |
| `aws:sagemaker:notebook-lifecycle-config` | `GenericManagement` | regional | `sagemaker:ListNotebookInstanceLifecycleConfigs` | `sagemaker:ListNotebookInstanceLifecycleConfigs` |
| `aws:sagemaker:pipeline` | `Workflow` | regional | `sagemaker:ListPipelines` | `sagemaker:ListPipelines` |
| `aws:sagemaker:processing-job` | `BatchJob` | regional | `sagemaker:ListProcessingJobs` | `sagemaker:ListProcessingJobs` |
| `aws:sagemaker:studio-lifecycle-config` | `GenericManagement` | regional | `sagemaker:ListStudioLifecycleConfigs` | `sagemaker:ListStudioLifecycleConfigs` |
| `aws:sagemaker:training-job` | `BatchJob` | regional | `sagemaker:ListTrainingJobs` | `sagemaker:ListTrainingJobs` |
| `aws:sagemaker:transform-job` | `BatchJob` | regional | `sagemaker:ListTransformJobs` | `sagemaker:ListTransformJobs` |
| `aws:secretsmanager:secret` | `Secret` | regional | `secretsmanager:ListSecrets` | `secretsmanager:ListSecrets` |
| `aws:securityhub:standard` | `SecurityService` | regional | `securityhub:GetEnabledStandards` | `securityhub:GetEnabledStandards` |
| `aws:servicecatalog:portfolio` | `AutomationService` | regional | `servicecatalog:ListPortfolios` | `servicecatalog:ListPortfolios` |
| `aws:sns:topic` | `Topic` | regional | `sns:ListTopics` | `sns:ListTopics` |
| `aws:sqs:queue` | `Queue` | regional | `sqs:ListQueues` | `sqs:ListQueues` |
| `aws:ssm-params:parameter` | `Secret` | regional | `ssm:DescribeParameters` | `ssm:DescribeParameters` |
| `aws:ssm:managed-instance` | `VirtualMachine` | regional | `ssm:DescribeInstanceInformation` | `ssm:DescribeInstanceInformation` |
| `aws:sso:instance` | `GenericManagement` | regional | `sso:ListInstances` | `sso:ListInstances` |
| `aws:stepfunctions:state_machine` | `Workflow` | regional | `states:ListStateMachines` | `states:ListStateMachines` |
| `aws:tgw:transit-gateway` | `TransitGateway` | regional | `ec2:DescribeTransitGateways` | `ec2:DescribeTransitGateways` |
| `aws:timestream:database` | `GenericData` | regional | `timestream:ListDatabases` | `timestream:ListDatabases` |
| `aws:vpc:vpc` | `VirtualNetwork` | regional | `vpc:DescribeVpcs` | `ec2:DescribeVpcs` |
| `aws:vpclattice:service-network` | `GenericNetwork` | regional | `vpc-lattice:ListServiceNetworks` | `vpc-lattice:ListServiceNetworks` |
| `aws:waf:web_acl` | `Firewall` | regional | `waf:ListWebACLs` | `wafv2:ListWebACLs` |

### 2.2 GCP (53 resource types)

| Resource type | Node type | Scope | Enumerate | Required permissions |
|---|---|---|---|---|
| `gcp:accesscontextmanager:access-policy` | `ConditionalPolicy` | global | `accesscontextmanager.accessPolicies.list` | `accesscontextmanager.accessPolicies.list` |
| `gcp:aiplatform:notebook` | `Notebook` | regional | `notebooks.projects.locations.instances.list` | `notebooks.instances.list` |
| `gcp:appengine:service` | `ApplicationPlatform` | global | `appengine.apps.services.list` | `appengine.services.list` |
| `gcp:artifactregistry:repository` | `ContainerRegistry` | regional | `artifactregistry.projects.locations.repositories.list` | `artifactregistry.repositories.list` |
| `gcp:batch:job` | `BatchJob` | regional | `batch.projects.locations.jobs.list` | `batch.jobs.list` |
| `gcp:bigquery:dataset` | `DataWarehouse` | global | `bigquery.datasets.list` | `bigquery.datasets.get` |
| `gcp:bigtableadmin:instance` | `NoSQLDatabase` | global | `bigtableadmin.projects.instances.list` | `bigtable.instances.list` |
| `gcp:certificatemanager:certificate` | `Certificate` | regional | `certificatemanager.projects.locations.certificates.list` | `certificatemanager.certs.list` |
| `gcp:cloudbuild:build` | `BuildWorker` | global | `cloudbuild.projects.builds.list` | `cloudbuild.builds.list` |
| `gcp:clouddeploy:delivery-pipeline` | `AutomationService` | regional | `clouddeploy.projects.locations.deliveryPipelines.list` | `clouddeploy.deliveryPipelines.list` |
| `gcp:cloudfunctions:function` | `ServerlessFunction` | global | `cloudfunctions.projects.locations.functions.list` | `cloudfunctions.functions.list` |
| `gcp:cloudidentity:group` | `Group` | global | `cloudidentity.groups.list` | `cloudidentity.groups.list` |
| `gcp:cloudkms:key-ring` | `EncryptionKey` | regional | `cloudkms.projects.locations.keyRings.list` | `cloudkms.keyRings.list` |
| `gcp:cloudscheduler:job` | `Scheduler` | regional | `cloudscheduler.projects.locations.jobs.list` | `cloudscheduler.jobs.list` |
| `gcp:cloudtasks:queue` | `Queue` | regional | `cloudtasks.projects.locations.queues.list` | `cloudtasks.queues.list` |
| `gcp:composer:environment` | `Workflow` | regional | `composer.projects.locations.environments.list` | `composer.environments.list` |
| `gcp:compute:disk` | `BlockStorage` | global | `compute.disks.aggregatedList` | `compute.disks.list` |
| `gcp:compute:firewall` | `Firewall` | global | `compute.firewalls.list` | `compute.firewalls.list` |
| `gcp:compute:forwarding-rule` | `LoadBalancer` | global | `compute.forwardingRules.aggregatedList` | `compute.forwardingRules.list` |
| `gcp:compute:instance` | `VirtualMachine` | global | `compute.instances.aggregatedList` | `compute.instances.list` |
| `gcp:compute:network` | `VirtualNetwork` | global | `compute.networks.list` | `compute.networks.list` |
| `gcp:compute:security-policy` | `Firewall` | global | `compute.securityPolicies.list` | `compute.securityPolicies.list` |
| `gcp:compute:subnetwork` | `Subnet` | region | `compute.subnetworks.aggregatedList` | `compute.subnetworks.list` |
| `gcp:container:cluster` | `KubernetesCluster` | global | `container.projects.locations.clusters.list` | `container.clusters.list` |
| `gcp:dataflow:job` | `AnalyticsService` | global | `dataflow.projects.jobs.aggregated` | `dataflow.jobs.list` |
| `gcp:dataproc:cluster` | `AnalyticsService` | regional | `dataproc.projects.regions.clusters.list` | `dataproc.clusters.list` |
| `gcp:datastream:stream` | `Workflow` | regional | `datastream.projects.locations.streams.list` | `datastream.streams.list` |
| `gcp:deploymentmanager:deployment` | `AutomationService` | global | `deploymentmanager.deployments.list` | `deploymentmanager.deployments.list` |
| `gcp:dns:managed-zone` | `DNS` | global | `dns.managedZones.list` | `dns.managedZones.list` |
| `gcp:eventarc:trigger` | `EventRule` | regional | `eventarc.projects.locations.triggers.list` | `eventarc.triggers.list` |
| `gcp:file:instance` | `FileStorage` | global | `file.projects.locations.instances.list` | `file.instances.list` |
| `gcp:firestore:database` | `NoSQLDatabase` | global | `firestore.projects.databases.list` | `datastore.databases.list` |
| `gcp:iam:role` | `Role` | global | `iam.projects.roles.list` | `iam.roles.list` |
| `gcp:iam:service-account` | `ServiceAccount` | global | `iam.projects.serviceAccounts.list` | `iam.serviceAccounts.list` |
| `gcp:iam:service-account-key` | `AccessKey` | project | `iam.projects.serviceAccounts.keys.list` | `iam.serviceAccountKeys.list` |
| `gcp:iam:workload-identity-pool` | `FederatedIdentity` | global | `iam.projects.locations.workloadIdentityPools.list` | `iam.workloadIdentityPools.list` |
| `gcp:iap:tunnel` | `PrivateEndpoint` | global | `iap.projects.iap_tunnel.locations.destGroups.list` | `iap.tunnelDestGroups.list` |
| `gcp:logging:sink` | `LoggingService` | global | `logging.projects.sinks.list` | `logging.sinks.list` |
| `gcp:monitoring:notification-channel` | `LoggingService` | global | `monitoring.projects.notificationChannels.list` | `monitoring.notificationChannels.list` |
| `gcp:networkconnectivity:hub` | `TransitGateway` | global | `networkconnectivity.projects.locations.global.hubs.list` | `networkconnectivity.hubs.list` |
| `gcp:orgpolicy:policy` | `OrganizationPolicy` | global | `orgpolicy.projects.policies.list` | `orgpolicy.policies.list` |
| `gcp:pubsub:topic` | `Topic` | global | `pubsub.projects.topics.list` | `pubsub.topics.list` |
| `gcp:redis:instance` | `Cache` | regional | `redis.projects.locations.instances.list` | `redis.instances.list` |
| `gcp:resourcemanager:folder` | `Folder` | global | `cloudresourcemanager.folders.list` | `resourcemanager.folders.list` |
| `gcp:resourcemanager:organization` | `Organization` | global | `cloudresourcemanager.organizations.search` | `resourcemanager.organizations.get` |
| `gcp:resourcemanager:project` | `Project` | global | `cloudresourcemanager.projects.get` | `resourcemanager.projects.list` |
| `gcp:run:service` | `ContainerService` | regional | `run.projects.locations.services.list` | `run.services.list` |
| `gcp:secretmanager:secret` | `Secret` | global | `secretmanager.projects.secrets.list` | `secretmanager.secrets.list` |
| `gcp:securitycenter:source` | `SecurityService` | global | `securitycenter.projects.sources.list` | `securitycenter.sources.list` |
| `gcp:spanner:instance` | `RelationalDatabase` | global | `spanner.projects.instances.list` | `spanner.instances.list` |
| `gcp:sqladmin:instance` | `RelationalDatabase` | global | `sql.instances.list` | `cloudsql.instances.list` |
| `gcp:storage:bucket` | `ObjectStorage` | global | `storage.buckets.list` | `storage.buckets.list` |
| `gcp:workflows:workflow` | `Workflow` | regional | `workflows.projects.locations.workflows.list` | `workflows.workflows.list` |

### 2.3 Azure (60 resource types)

| Resource type | Node type | Scope | Enumerate | Required permissions |
|---|---|---|---|---|
| `azure:aci:containergroup` | `ContainerService` | global | `arg:microsoft.containerinstance/containergroups` | `Microsoft.ContainerInstance/containergroups/read` |
| `azure:aks:cluster` | `KubernetesCluster` | global | `arg:microsoft.containerservice/managedclusters` | `Microsoft.ContainerService/managedclusters/read` |
| `azure:apim:service` | `APIGateway` | global | `arg:microsoft.apimanagement/service` | `Microsoft.ApiManagement/service/read` |
| `azure:app:containerapp` | `ContainerService` | global | `arg:microsoft.app/containerapps` | `Microsoft.App/containerapps/read` |
| `azure:appconfig:store` | `Secret` | global | `arg:microsoft.appconfiguration/configurationstores` | `Microsoft.AppConfiguration/configurationstores/read` |
| `azure:automation:account` | `AutomationService` | global | `arg:microsoft.automation/automationaccounts` | `Microsoft.Automation/automationaccounts/read` |
| `azure:batch:account` | `BatchJob` | global | `arg:microsoft.batch/batchaccounts` | `Microsoft.Batch/batchaccounts/read` |
| `azure:cache:redis` | `Cache` | global | `arg:microsoft.cache/redis` | `Microsoft.Cache/redis/read` |
| `azure:cdn:profile` | `LoadBalancer` | global | `arg:microsoft.cdn/profiles` | `Microsoft.Cdn/profiles/read` |
| `azure:cognitiveservices:account` | `AnalyticsService` | global | `arg:microsoft.cognitiveservices/accounts` | `Microsoft.CognitiveServices/accounts/read` |
| `azure:compute:disk` | `BlockStorage` | global | `arg:microsoft.compute/disks` | `Microsoft.Compute/disks/read` |
| `azure:compute:snapshot` | `Snapshot` | global | `arg:microsoft.compute/snapshots` | `Microsoft.Compute/snapshots/read` |
| `azure:compute:vm` | `VirtualMachine` | global | `arg:microsoft.compute/virtualmachines` | `Microsoft.Compute/virtualmachines/read` |
| `azure:compute:vmss` | `VirtualMachine` | global | `arg:microsoft.compute/virtualmachinescalesets` | `Microsoft.Compute/virtualmachinescalesets/read` |
| `azure:containerregistry:registry` | `ContainerRegistry` | global | `arg:microsoft.containerregistry/registries` | `Microsoft.ContainerRegistry/registries/read` |
| `azure:databricks:workspace` | `AnalyticsService` | global | `arg:microsoft.databricks/workspaces` | `Microsoft.Databricks/workspaces/read` |
| `azure:datafactory:factory` | `AutomationService` | global | `arg:microsoft.datafactory/factories` | `Microsoft.DataFactory/factories/read` |
| `azure:datalake:store` | `DataLake` | global | `arg:microsoft.datalakestore/accounts` | `Microsoft.DataLakeStore/accounts/read` |
| `azure:documentdb:cosmos` | `NoSQLDatabase` | global | `arg:microsoft.documentdb/databaseaccounts` | `Microsoft.DocumentDB/databaseaccounts/read` |
| `azure:entra:group` | `Group` | global | `msgraph:groups.list` | `Group.Read.All` |
| `azure:entra:serviceprincipal` | `ApplicationIdentity` | global | `msgraph:servicePrincipals.list` | `Application.Read.All` |
| `azure:entra:user` | `HumanIdentity` | global | `msgraph:users.list` | `User.Read.All` |
| `azure:eventgrid:topic` | `Topic` | global | `arg:microsoft.eventgrid/topics` | `Microsoft.EventGrid/topics/read` |
| `azure:eventhub:namespace` | `EventBus` | global | `arg:microsoft.eventhub/namespaces` | `Microsoft.EventHub/namespaces/read` |
| `azure:hdinsight:cluster` | `AnalyticsService` | global | `arg:microsoft.hdinsight/clusters` | `Microsoft.HDInsight/clusters/read` |
| `azure:keyvault:managedhsm` | `EncryptionKey` | global | `arg:microsoft.keyvault/managedhsms` | `Microsoft.KeyVault/managedhsms/read` |
| `azure:keyvault:vault` | `Secret` | global | `arg:microsoft.keyvault/vaults` | `Microsoft.KeyVault/vaults/read` |
| `azure:kusto:cluster` | `AnalyticsService` | global | `arg:microsoft.kusto/clusters` | `Microsoft.Kusto/clusters/read` |
| `azure:logic:workflow` | `Workflow` | global | `arg:microsoft.logic/workflows` | `Microsoft.Logic/workflows/read` |
| `azure:managedidentity:userassigned` | `ManagedIdentity` | global | `arg:microsoft.managedidentity/userassignedidentities` | `Microsoft.ManagedIdentity/userassignedidentities/read` |
| `azure:management:managementgroup` | `ManagementGroup` | tenant | `Microsoft.Management/managementGroups (list)` | `Microsoft.Management/managementGroups/read` |
| `azure:mariadb:server` | `RelationalDatabase` | global | `arg:microsoft.dbformariadb/servers` | `Microsoft.DBforMariaDB/servers/read` |
| `azure:ml:workspace` | `AnalyticsService` | global | `arg:microsoft.machinelearningservices/workspaces` | `Microsoft.MachineLearningServices/workspaces/read` |
| `azure:mysql:flexibleserver` | `RelationalDatabase` | global | `arg:microsoft.dbformysql/flexibleservers` | `Microsoft.DBforMySQL/flexibleservers/read` |
| `azure:netapp:account` | `FileStorage` | global | `arg:microsoft.netapp/netappaccounts` | `Microsoft.NetApp/netappaccounts/read` |
| `azure:network:appgateway` | `LoadBalancer` | global | `arg:microsoft.network/applicationgateways` | `Microsoft.Network/applicationgateways/read` |
| `azure:network:firewall` | `Firewall` | global | `arg:microsoft.network/azurefirewalls` | `Microsoft.Network/azurefirewalls/read` |
| `azure:network:loadbalancer` | `LoadBalancer` | global | `arg:microsoft.network/loadbalancers` | `Microsoft.Network/loadbalancers/read` |
| `azure:network:nic` | `NetworkInterface` | region | `arg:microsoft.network/networkinterfaces` | `Microsoft.Network/networkInterfaces/read` |
| `azure:network:nsg` | `Firewall` | global | `arg:microsoft.network/networksecuritygroups` | `Microsoft.Network/networksecuritygroups/read` |
| `azure:network:privateendpoint` | `PrivateEndpoint` | region | `arg:microsoft.network/privateendpoints` | `Microsoft.Network/privateEndpoints/read` |
| `azure:network:subnet` | `Subnet` | region | `arg:microsoft.network/virtualnetworks/subnets` | `Microsoft.Network/virtualNetworks/subnets/read` |
| `azure:network:vnet` | `VirtualNetwork` | global | `arg:microsoft.network/virtualnetworks` | `Microsoft.Network/virtualnetworks/read` |
| `azure:notificationhubs:namespace` | `Topic` | global | `arg:microsoft.notificationhubs/namespaces` | `Microsoft.NotificationHubs/namespaces/read` |
| `azure:postgresql:flexibleserver` | `RelationalDatabase` | global | `arg:microsoft.dbforpostgresql/flexibleservers` | `Microsoft.DBforPostgreSQL/flexibleservers/read` |
| `azure:postgresql:server` | `RelationalDatabase` | global | `arg:microsoft.dbforpostgresql/servers` | `Microsoft.DBforPostgreSQL/flexibleServers/read` |
| `azure:purview:account` | `AnalyticsService` | global | `arg:microsoft.purview/accounts` | `Microsoft.Purview/accounts/read` |
| `azure:recoveryservices:vault` | `Backup` | global | `arg:microsoft.recoveryservices/vaults` | `Microsoft.RecoveryServices/vaults/read` |
| `azure:resources:resourcegroup` | `ResourceGroup` | subscription | `Microsoft.Resources/subscriptions/resourceGroups (list)` | `Microsoft.Resources/subscriptions/resourceGroups/read` |
| `azure:resources:subscription` | `Subscription` | tenant | `Microsoft.Resources/subscriptions (list)` | `Microsoft.Resources/subscriptions/read` |
| `azure:search:service` | `SearchService` | global | `arg:microsoft.search/searchservices` | `Microsoft.Search/searchservices/read` |
| `azure:servicebus:namespace` | `Queue` | global | `arg:microsoft.servicebus/namespaces` | `Microsoft.ServiceBus/namespaces/read` |
| `azure:servicefabric:cluster` | `ContainerCluster` | global | `arg:microsoft.servicefabric/clusters` | `Microsoft.ServiceFabric/clusters/read` |
| `azure:signalr:service` | `GenericMessaging` | global | `arg:microsoft.signalrservice/signalr` | `Microsoft.SignalRService/signalr/read` |
| `azure:sql:server` | `RelationalDatabase` | global | `arg:microsoft.sql/servers` | `Microsoft.Sql/servers/read` |
| `azure:storage:account` | `ObjectStorage` | global | `arg:microsoft.storage/storageaccounts` | `Microsoft.Storage/storageaccounts/read` |
| `azure:streamanalytics:job` | `AnalyticsService` | global | `arg:microsoft.streamanalytics/streamingjobs` | `Microsoft.StreamAnalytics/streamingjobs/read` |
| `azure:synapse:workspace` | `AnalyticsService` | global | `arg:microsoft.synapse/workspaces` | `Microsoft.Synapse/workspaces/read` |
| `azure:web:site` | `ApplicationPlatform` | global | `arg:microsoft.web/sites` | `Microsoft.Web/sites/read` |
| `azure:web:staticsite` | `ApplicationPlatform` | global | `arg:microsoft.web/staticsites` | `Microsoft.Web/staticsites/read` |

> `+N detail` marks resources with an N-step enrichment chain (e.g. list → get → download) in the
> registry's `detail` field. See `providers/*.json` for the full recipe (bind/capture per step).

### 2.4 Fact / relationship recipes

Node recipes yield inventory; **fact recipes** collect the policies, bindings, trust, memberships,
network rules, and credentials that back *edges*. Guardrail facts (SCPs, deny assignments) have an
empty `backs` — they constrain edges to BLOCKED. `providers/*.json` `facts[]` are the registries.

**AWS** (8 fact recipes)

| Fact kind | Collect | Backs edges | Required permissions |
|---|---|---|---|
| `identity_policy` | `iam:ListRolePolicies + iam:GetRolePolicy (inline) / iam:ListAttachedRolePolicies (managed)` | `HasPermission`, `HasPolicy` | `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListGroupsForUser` |
| `managed_policy` | `iam:GetPolicy + iam:GetPolicyVersion` | `HasPolicy`, `HasPermission` | `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicies` |
| `trust_policy` | `iam:GetRole (AssumeRolePolicyDocument)` | `CanAssume`, `CrossAccountTrust`, `CanFederateAs` | `iam:GetRole`, `iam:ListRoles` |
| `resource_policy` | `s3:GetBucketPolicy / kms:GetKeyPolicy / secretsmanager:GetResourcePolicy / sns:GetTopicAttributes / sqs:GetQueueAttributes / lambda:GetPolicy / ecr:GetRepositoryPolicy` | `HasPolicy`, `CrossAccountTrust`, `ExposedToInternet`, `ExposedToAccount`, `CanReadSecret`, `CanDecrypt`, `CanReadData` | `s3:GetBucketPolicy`, `kms:GetKeyPolicy`, `secretsmanager:GetResourcePolicy`, `sns:GetTopicAttributes`, `sqs:GetQueueAttributes`, `lambda:GetPolicy`, `ecr:GetRepositoryPolicy` |
| `scp` | `organizations:ListPoliciesForTarget + organizations:DescribePolicy` | _(guardrail — blocks)_ | `organizations:ListPoliciesForTarget`, `organizations:DescribePolicy` |
| `membership` | `iam:GetGroup` | `MemberOf` | `iam:GetGroup`, `iam:ListGroupsForUser` |
| `network_rule` | `ec2:DescribeSecurityGroups + ec2:DescribeNetworkInterfaces` | `CanNetworkReach`, `CanReachPort`, `ExposedToInternet`, `PrivateReachability` | `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables` |
| `credential` | `iam:ListAccessKeys` | `CredentialsFor`, `ExposesCredential` | `iam:ListAccessKeys` |

**GCP** (5 fact recipes)

| Fact kind | Collect | Backs edges | Required permissions |
|---|---|---|---|
| `iam_binding` | `getIamPolicy (resourcemanager.{projects,folders,organizations}.getIamPolicy)` | `HasRole`, `HasPermission`, `CanImpersonate` | `resourcemanager.projects.getIamPolicy`, `resourcemanager.folders.getIamPolicy`, `resourcemanager.organizations.getIamPolicy` |
| `resource_policy` | `<service>.getIamPolicy on the resource` | `HasPolicy`, `CanReadData`, `CanDecrypt`, `CanReadSecret`, `CanImpersonate` | `storage.buckets.getIamPolicy`, `cloudkms.cryptoKeys.getIamPolicy`, `secretmanager.secrets.getIamPolicy`, `iam.serviceAccounts.getIamPolicy` |
| `public` | `allUsers / allAuthenticatedUsers bindings in a getIamPolicy result` | `ExposedToInternet`, `ExposedToTenant` | `storage.buckets.getIamPolicy`, `run.services.getIamPolicy` |
| `membership` | `cloudidentity.groups.memberships.list` | `MemberOf` | `cloudidentity.groups.memberships.list` |
| `workload_identity` | `iam.serviceAccounts.getIamPolicy (WIF pool bindings) / getOpenIdToken` | `CanFederateAs`, `FederatesTo` | `iam.workloadIdentityPools.get`, `iam.serviceAccounts.getIamPolicy` |

**Azure** (9 fact recipes)

| Fact kind | Collect | Backs edges | Required permissions |
|---|---|---|---|
| `role_assignment` | `Microsoft.Authorization/roleAssignments (list)` | `HasRole`, `HasPermission` | `Microsoft.Authorization/roleAssignments/read` |
| `role_definition` | `Microsoft.Authorization/roleDefinitions (list)` | `HasPermission` | `Microsoft.Authorization/roleDefinitions/read` |
| `deny_assignment` | `Microsoft.Authorization/denyAssignments (list)` | _(guardrail — blocks)_ | `Microsoft.Authorization/denyAssignments/read` |
| `mg_hierarchy` | `Microsoft.Management/managementGroups (list + descendants)` | `Contains`, `CanEnterSubscription`, `CanEnterTenant` | `Microsoft.Management/managementGroups/read` |
| `entra_role_assignment` | `msgraph roleManagement.directory.roleAssignments + roleEligibilityScheduleInstances` | `HasRole`, `CanGrantPermission` | `RoleManagement.Read.Directory` |
| `entra_owner` | `msgraph owners (application/servicePrincipal/group owners)` | `CanControl`, `CanCreateCredentialFor` | `Application.Read.All`, `Directory.Read.All` |
| `entra_app_role` | `msgraph appRoleAssignments / oauth2PermissionGrants` | `HasPermission`, `CanGrantPermission` | `Application.Read.All`, `Directory.Read.All` |
| `membership` | `msgraph group members (transitiveMembers)` | `MemberOf` | `GroupMember.Read.All` |
| `resource_policy` | `Key Vault access policies / storage account public access / resource-scope role assignments` | `HasPolicy`, `CanReadSecret`, `CanDecrypt`, `ExposedToInternet` | `Microsoft.KeyVault/vaults/read`, `Microsoft.Storage/storageAccounts/read` |

---

## 3. Generic type → concrete resources

The corpus inverted — which real resources realize each generic type across clouds. The completeness
view: what is backed by collection everywhere vs. what is derivation-only.

#### `HumanIdentity`
- **AWS:** `aws:iam:user`
- **Azure:** `azure:entra:user`

#### `ApplicationIdentity`
- **Azure:** `azure:entra:serviceprincipal`

#### `FederatedIdentity`
- **AWS:** `aws:cognito:user_pool`, `aws:ds:directory`, `aws:rolesanywhere:trust-anchor`
- **GCP:** `gcp:iam:workload-identity-pool`

#### `Group`
- **AWS:** `aws:iam:group`
- **GCP:** `gcp:cloudidentity:group`
- **Azure:** `azure:entra:group`

#### `Role`
- **AWS:** `aws:iam:role`
- **GCP:** `gcp:iam:role`

#### `ServiceAccount`
- **GCP:** `gcp:iam:service-account`

#### `ManagedIdentity`
- **Azure:** `azure:managedidentity:userassigned`

#### `Organization`
- **GCP:** `gcp:resourcemanager:organization`

#### `ManagementGroup`
- **Azure:** `azure:management:managementgroup`

#### `Folder`
- **GCP:** `gcp:resourcemanager:folder`

#### `Account`
- **AWS:** `aws:account:region`, `aws:organizations:account`

#### `Subscription`
- **Azure:** `azure:resources:subscription`

#### `Project`
- **GCP:** `gcp:resourcemanager:project`

#### `ResourceGroup`
- **Azure:** `azure:resources:resourcegroup`

#### `VirtualMachine`
- **AWS:** `aws:ec2:instance`, `aws:lightsail:instance`, `aws:ssm:managed-instance`
- **GCP:** `gcp:compute:instance`
- **Azure:** `azure:compute:vm`, `azure:compute:vmss`

#### `ServerlessFunction`
- **AWS:** `aws:lambda:function`
- **GCP:** `gcp:cloudfunctions:function`

#### `ContainerService`
- **GCP:** `gcp:run:service`
- **Azure:** `azure:aci:containergroup`, `azure:app:containerapp`

#### `ContainerCluster`
- **AWS:** `aws:ecs:cluster`
- **Azure:** `azure:servicefabric:cluster`

#### `KubernetesCluster`
- **AWS:** `aws:eks:cluster`
- **GCP:** `gcp:container:cluster`
- **Azure:** `azure:aks:cluster`

#### `BuildWorker`
- **AWS:** `aws:codebuild:project`, `aws:imagebuilder:image_pipeline`
- **GCP:** `gcp:cloudbuild:build`

#### `BatchJob`
- **AWS:** `aws:batch:job-queue`, `aws:glue:job`, `aws:sagemaker:processing-job`, `aws:sagemaker:training-job`, `aws:sagemaker:transform-job`
- **GCP:** `gcp:batch:job`
- **Azure:** `azure:batch:account`

#### `Notebook`
- **AWS:** `aws:sagemaker:notebook-instance`
- **GCP:** `gcp:aiplatform:notebook`

#### `ApplicationPlatform`
- **AWS:** `aws:amplify:app`, `aws:apprunner:service`, `aws:beanstalk:environment`
- **GCP:** `gcp:appengine:service`
- **Azure:** `azure:web:site`, `azure:web:staticsite`

#### `GenericCompute`
- **AWS:** `aws:autoscaling:auto-scaling-group`

#### `ObjectStorage`
- **AWS:** `aws:s3:bucket`
- **GCP:** `gcp:storage:bucket`
- **Azure:** `azure:storage:account`

#### `FileStorage`
- **AWS:** `aws:efs:filesystem`, `aws:fsx:file_system`
- **GCP:** `gcp:file:instance`
- **Azure:** `azure:netapp:account`

#### `BlockStorage`
- **GCP:** `gcp:compute:disk`
- **Azure:** `azure:compute:disk`

#### `Backup`
- **AWS:** `aws:backup:vault`
- **Azure:** `azure:recoveryservices:vault`

#### `Snapshot`
- **AWS:** `aws:ebs:snapshot`
- **Azure:** `azure:compute:snapshot`

#### `ArtifactRepository`
- **AWS:** `aws:codeartifact:repository`, `aws:codecommit:repository`

#### `ContainerRegistry`
- **AWS:** `aws:ecr:repository`
- **GCP:** `gcp:artifactregistry:repository`
- **Azure:** `azure:containerregistry:registry`

#### `RelationalDatabase`
- **AWS:** `aws:rds:db_instance`
- **GCP:** `gcp:spanner:instance`, `gcp:sqladmin:instance`
- **Azure:** `azure:mariadb:server`, `azure:mysql:flexibleserver`, `azure:postgresql:flexibleserver`, `azure:postgresql:server`, `azure:sql:server`

#### `NoSQLDatabase`
- **AWS:** `aws:documentdb:db_cluster`, `aws:dynamodb:table`, `aws:keyspaces:keyspace`, `aws:neptune:db_cluster`
- **GCP:** `gcp:bigtableadmin:instance`, `gcp:firestore:database`
- **Azure:** `azure:documentdb:cosmos`

#### `DataWarehouse`
- **AWS:** `aws:redshift:cluster`
- **GCP:** `gcp:bigquery:dataset`

#### `Cache`
- **AWS:** `aws:elasticache:cache_cluster`, `aws:memorydb:cluster`
- **GCP:** `gcp:redis:instance`
- **Azure:** `azure:cache:redis`

#### `SearchService`
- **AWS:** `aws:opensearch:domain`
- **Azure:** `azure:search:service`

#### `AnalyticsService`
- **AWS:** `aws:athena:workgroup`, `aws:emr:cluster`, `aws:quicksight:dashboard`
- **GCP:** `gcp:dataflow:job`, `gcp:dataproc:cluster`
- **Azure:** `azure:cognitiveservices:account`, `azure:databricks:workspace`, `azure:hdinsight:cluster`, `azure:kusto:cluster`, `azure:ml:workspace`, `azure:purview:account`, `azure:streamanalytics:job`, `azure:synapse:workspace`

#### `DataLake`
- **AWS:** `aws:lakeformation:resource`
- **Azure:** `azure:datalake:store`

#### `GenericData`
- **AWS:** `aws:qldb:ledger`, `aws:timestream:database`

#### `Queue`
- **AWS:** `aws:kinesis:stream`, `aws:mq:broker`, `aws:msk:cluster`, `aws:sqs:queue`
- **GCP:** `gcp:cloudtasks:queue`
- **Azure:** `azure:servicebus:namespace`

#### `Topic`
- **AWS:** `aws:sns:topic`
- **GCP:** `gcp:pubsub:topic`
- **Azure:** `azure:eventgrid:topic`, `azure:notificationhubs:namespace`

#### `EventBus`
- **AWS:** `aws:eventbridge:event_bus`
- **Azure:** `azure:eventhub:namespace`

#### `EventRule`
- **GCP:** `gcp:eventarc:trigger`

#### `Workflow`
- **AWS:** `aws:appflow:flow`, `aws:codepipeline:pipeline`, `aws:datapipeline:pipeline`, `aws:sagemaker:pipeline`, `aws:stepfunctions:state_machine`
- **GCP:** `gcp:composer:environment`, `gcp:datastream:stream`, `gcp:workflows:workflow`
- **Azure:** `azure:logic:workflow`

#### `Scheduler`
- **GCP:** `gcp:cloudscheduler:job`

#### `APIGateway`
- **AWS:** `aws:apigateway:rest-api`
- **Azure:** `azure:apim:service`

#### `GenericMessaging`
- **Azure:** `azure:signalr:service`

#### `Secret`
- **AWS:** `aws:secretsmanager:secret`, `aws:ssm-params:parameter`
- **GCP:** `gcp:secretmanager:secret`
- **Azure:** `azure:appconfig:store`, `azure:keyvault:vault`

#### `AccessKey`
- **AWS:** `aws:iam:access-key`
- **GCP:** `gcp:iam:service-account-key`

#### `Certificate`
- **AWS:** `aws:acm:certificate`
- **GCP:** `gcp:certificatemanager:certificate`

#### `EncryptionKey`
- **AWS:** `aws:cloudhsm:cluster`, `aws:kms:key`
- **GCP:** `gcp:cloudkms:key-ring`
- **Azure:** `azure:keyvault:managedhsm`

#### `SigningKey`
- **AWS:** `aws:acmpca:certificate-authority`

#### `VirtualNetwork`
- **AWS:** `aws:vpc:vpc`
- **GCP:** `gcp:compute:network`
- **Azure:** `azure:network:vnet`

#### `Subnet`
- **AWS:** `aws:ec2:subnet`
- **GCP:** `gcp:compute:subnetwork`
- **Azure:** `azure:network:subnet`

#### `SecurityGroup`
- **AWS:** `aws:ec2:security-group`

#### `Firewall`
- **AWS:** `aws:networkfirewall:firewall`, `aws:waf:web_acl`
- **GCP:** `gcp:compute:firewall`, `gcp:compute:security-policy`
- **Azure:** `azure:network:firewall`, `azure:network:nsg`

#### `Route`
- **AWS:** `aws:ec2:route-table`

#### `LoadBalancer`
- **AWS:** `aws:cloudfront:distribution`, `aws:elb:load_balancer`
- **GCP:** `gcp:compute:forwarding-rule`
- **Azure:** `azure:cdn:profile`, `azure:network:appgateway`, `azure:network:loadbalancer`

#### `PrivateEndpoint`
- **AWS:** `aws:ec2:vpc-endpoint`
- **GCP:** `gcp:iap:tunnel`
- **Azure:** `azure:network:privateendpoint`

#### `PublicEndpoint`
- **AWS:** `aws:globalaccelerator:accelerator`

#### `VPN`
- **AWS:** `aws:directconnect:connection`

#### `TransitGateway`
- **AWS:** `aws:tgw:transit-gateway`
- **GCP:** `gcp:networkconnectivity:hub`

#### `DNS`
- **AWS:** `aws:route53:hosted_zone`
- **GCP:** `gcp:dns:managed-zone`

#### `NetworkInterface`
- **AWS:** `aws:ec2:network-interface`
- **Azure:** `azure:network:nic`

#### `GenericNetwork`
- **AWS:** `aws:appmesh:mesh`, `aws:vpclattice:service-network`

#### `IAMPolicy`
- **AWS:** `aws:iam:policy`

#### `ResourcePolicy`
- **AWS:** `aws:ram:resource_share`

#### `OrganizationPolicy`
- **GCP:** `gcp:orgpolicy:policy`

#### `ConditionalPolicy`
- **GCP:** `gcp:accesscontextmanager:access-policy`

#### `LoggingService`
- **AWS:** `aws:cloudtrail:trail`, `aws:cloudwatch:log_group`
- **GCP:** `gcp:logging:sink`, `gcp:monitoring:notification-channel`

#### `SecurityService`
- **AWS:** `aws:accessanalyzer:analyzer`, `aws:detective:graph`, `aws:firewallmanager:policy`, `aws:guardduty:detector`, `aws:inspector:finding`, `aws:macie:classification-job`, `aws:securityhub:standard`
- **GCP:** `gcp:securitycenter:source`

#### `ConfigurationService`
- **AWS:** `aws:config:config-rule`

#### `AutomationService`
- **AWS:** `aws:cloudformation:stack`, `aws:codedeploy:application`, `aws:opsworks:stack`, `aws:servicecatalog:portfolio`
- **GCP:** `gcp:clouddeploy:delivery-pipeline`, `gcp:deploymentmanager:deployment`
- **Azure:** `azure:automation:account`, `azure:datafactory:factory`

#### `GenericManagement`
- **AWS:** `aws:controltower:landing_zone`, `aws:sagemaker:notebook-lifecycle-config`, `aws:sagemaker:studio-lifecycle-config`, `aws:sso:instance`

#### `MLModel`
- **AWS:** `aws:bedrock:custom_model`, `aws:sagemaker:model`

### 3.x Derivation-only / abstract types

Generic types with no directly-collected resource — they arise from derivation, identity
expansion, or as class-level fallbacks:

`MachineIdentity`, `WorkloadIdentity`, `ServiceIdentity`, `ExternalIdentity`, `AnonymousIdentity`, `GenericIdentity`, `CloudProvider`, `Tenant`, `Namespace`, `GenericBoundary`, `Container`, `ContainerTask`, `KubernetesWorkload`, `GenericStorage`, `Webhook`, `API`, `Credential`, `APIKey`, `SSHKey`, `Token`, `Password`, `ConnectionString`, `GenericSecret`, `Peering`, `NAT`, `TrustPolicy`, `PermissionBoundary`, `ServiceControlPolicy`, `GenericPolicy`, `RemoteManagementService`

---

## 4. Service coverage

Provider services and the generic types they contribute. `attack_relevance` is the curated risk
rating; `collected: false` marks a real service RAGE recognizes but doesn't yet enumerate as nodes.

### 4.1 AWS (91 services)

| Service | Name | Generic types | Relevance | Collected |
|---|---|---|---|---|
| `aws:accessanalyzer` | IAM Access Analyzer | `SecurityService` | low | yes |
| `aws:account` | Account Management | `Account` | medium | yes |
| `aws:acm` | Certificate Manager | `Certificate` | medium | yes |
| `aws:acmpca` | ACM Private CA | `SigningKey` | high | yes |
| `aws:amplify` | Amplify | `ApplicationPlatform` | medium | yes |
| `aws:apigateway` | API Gateway | `APIGateway` | high | yes |
| `aws:appflow` | AppFlow | `Workflow` | medium | yes |
| `aws:appmesh` | App Mesh | `GenericNetwork` | low | yes |
| `aws:apprunner` | App Runner | `ApplicationPlatform` | high | yes |
| `aws:athena` | Athena | `AnalyticsService` | medium | yes |
| `aws:autoscaling` | EC2 Auto Scaling | `GenericCompute` | high | yes |
| `aws:backup` | AWS Backup | `Backup` | medium | yes |
| `aws:batch` | Batch | `BatchJob` | high | yes |
| `aws:beanstalk` | Elastic Beanstalk | `ApplicationPlatform` | high | yes |
| `aws:bedrock` | Bedrock | `MLModel` | medium | yes |
| `aws:cloudformation` | CloudFormation | `AutomationService` | high | yes |
| `aws:cloudfront` | CloudFront | `LoadBalancer` | medium | yes |
| `aws:cloudhsm` | CloudHSM | `EncryptionKey` | medium | yes |
| `aws:cloudtrail` | CloudTrail | `LoggingService` | high | yes |
| `aws:cloudwatch` | CloudWatch/Logs | `LoggingService` | medium | yes |
| `aws:codeartifact` | CodeArtifact | `ArtifactRepository` | medium | yes |
| `aws:codebuild` | CodeBuild | `BuildWorker` | high | yes |
| `aws:codecommit` | CodeCommit | `ArtifactRepository` | medium | yes |
| `aws:codedeploy` | CodeDeploy | `AutomationService` | high | yes |
| `aws:codepipeline` | CodePipeline | `Workflow` | high | yes |
| `aws:cognito` | Cognito | `FederatedIdentity` | high | yes |
| `aws:config` | AWS Config | `ConfigurationService` | medium | yes |
| `aws:controltower` | Control Tower | `GenericManagement` | medium | yes |
| `aws:datapipeline` | Data Pipeline | `Workflow` | high | yes |
| `aws:detective` | Detective | `SecurityService` | low | yes |
| `aws:directconnect` | Direct Connect | `VPN` | low | yes |
| `aws:documentdb` | DocumentDB | `NoSQLDatabase` | medium | yes |
| `aws:ds` | Directory Service | `FederatedIdentity` | medium | yes |
| `aws:dynamodb` | DynamoDB | `NoSQLDatabase` | high | yes |
| `aws:ebs` | EBS | `Snapshot` | high | yes |
| `aws:ec2` | EC2 | `NetworkInterface`, `PrivateEndpoint`, `Route`, `SecurityGroup`, `Subnet`, `VirtualMachine` | high | yes |
| `aws:ecr` | ECR | `ContainerRegistry` | high | yes |
| `aws:ecs` | ECS/Fargate | `ContainerCluster` | high | yes |
| `aws:efs` | EFS | `FileStorage` | medium | yes |
| `aws:eks` | EKS | `KubernetesCluster` | high | yes |
| `aws:elasticache` | ElastiCache | `Cache` | medium | yes |
| `aws:elb` | ELB/ALB/NLB | `LoadBalancer` | high | yes |
| `aws:emr` | EMR | `AnalyticsService` | high | yes |
| `aws:eventbridge` | EventBridge | `EventBus` | high | yes |
| `aws:firewallmanager` | Firewall Manager | `SecurityService` | low | yes |
| `aws:fsx` | FSx | `FileStorage` | medium | yes |
| `aws:globalaccelerator` | Global Accelerator | `PublicEndpoint` | low | yes |
| `aws:glue` | Glue | `BatchJob` | high | yes |
| `aws:guardduty` | GuardDuty | `SecurityService` | high | yes |
| `aws:iam` | IAM | `AccessKey`, `Group`, `HumanIdentity`, `IAMPolicy`, `Role` | high | yes |
| `aws:imagebuilder` | EC2 Image Builder | `BuildWorker` | high | yes |
| `aws:inspector` | Inspector | `SecurityService` | low | yes |
| `aws:keyspaces` | Keyspaces | `NoSQLDatabase` | low | yes |
| `aws:kinesis` | Kinesis | `Queue` | low | yes |
| `aws:kms` | KMS | `EncryptionKey` | high | yes |
| `aws:lakeformation` | Lake Formation | `DataLake` | high | yes |
| `aws:lambda` | Lambda | `ServerlessFunction` | high | yes |
| `aws:lightsail` | Lightsail | `VirtualMachine` | medium | yes |
| `aws:macie` | Macie | `SecurityService` | low | yes |
| `aws:memorydb` | MemoryDB | `Cache` | low | yes |
| `aws:mq` | Amazon MQ | `Queue` | low | yes |
| `aws:msk` | MSK (Kafka) | `Queue` | low | yes |
| `aws:neptune` | Neptune | `NoSQLDatabase` | medium | yes |
| `aws:networkfirewall` | Network Firewall | `Firewall` | medium | yes |
| `aws:opensearch` | OpenSearch | `SearchService` | high | yes |
| `aws:opsworks` | OpsWorks | `AutomationService` | medium | yes |
| `aws:organizations` | Organizations | `Account` | high | yes |
| `aws:qldb` | QLDB | `GenericData` | low | yes |
| `aws:quicksight` | QuickSight | `AnalyticsService` | medium | yes |
| `aws:ram` | Resource Access Manager | `ResourcePolicy` | high | yes |
| `aws:rds` | RDS/Aurora | `RelationalDatabase` | high | yes |
| `aws:redshift` | Redshift | `DataWarehouse` | high | yes |
| `aws:rolesanywhere` | IAM Roles Anywhere | `FederatedIdentity` | high | yes |
| `aws:route53` | Route 53 | `DNS` | medium | yes |
| `aws:s3` | S3 | `ObjectStorage` | high | yes |
| `aws:sagemaker` | SageMaker | `BatchJob`, `GenericManagement`, `MLModel`, `Notebook`, `Workflow` | high | yes |
| `aws:secretsmanager` | Secrets Manager | `Secret` | high | yes |
| `aws:securityhub` | Security Hub | `SecurityService` | medium | yes |
| `aws:servicecatalog` | Service Catalog | `AutomationService` | medium | yes |
| `aws:sns` | SNS | `Topic` | medium | yes |
| `aws:sqs` | SQS | `Queue` | medium | yes |
| `aws:ssm` | Systems Manager | `VirtualMachine` | high | yes |
| `aws:ssm-params` | SSM Parameter Store | `Secret` | high | yes |
| `aws:sso` | IAM Identity Center | `GenericManagement` | high | yes |
| `aws:stepfunctions` | Step Functions | `Workflow` | high | yes |
| `aws:sts` | STS | `Token`, `Role` | high | no |
| `aws:tgw` | Transit Gateway | `TransitGateway` | high | yes |
| `aws:timestream` | Timestream | `GenericData` | low | yes |
| `aws:vpc` | VPC | `VirtualNetwork` | high | yes |
| `aws:vpclattice` | VPC Lattice | `GenericNetwork` | medium | yes |
| `aws:waf` | WAF/Shield | `Firewall` | low | yes |

### 4.2 GCP (46 services)

| Service | Name | Generic types | Relevance | Collected |
|---|---|---|---|---|
| `gcp:accesscontextmanager` | Access Context Manager / VPC-SC | `ConditionalPolicy` | high | yes |
| `gcp:aiplatform` | Vertex AI / Workbench | `Notebook` | high | yes |
| `gcp:appengine` | App Engine | `ApplicationPlatform` | high | yes |
| `gcp:artifactregistry` | Container Registry (legacy GCR) | `ContainerRegistry` | high | yes |
| `gcp:batch` | Batch | `BatchJob` | medium | yes |
| `gcp:bigquery` | BigQuery | `DataWarehouse` | high | yes |
| `gcp:bigtableadmin` | Bigtable | `NoSQLDatabase` | medium | yes |
| `gcp:certificatemanager` | Certificate Manager / CAS | `Certificate` | medium | yes |
| `gcp:cloudasset` | Cloud Asset Inventory | `ConfigurationService` | low | no |
| `gcp:cloudbuild` | Cloud Build | `BuildWorker` | high | yes |
| `gcp:clouddeploy` | Cloud Deploy | `AutomationService` | high | yes |
| `gcp:cloudfunctions` | Cloud Functions | `ServerlessFunction` | high | yes |
| `gcp:cloudidentity` | Cloud Identity / Workspace | `Group` | high | yes |
| `gcp:cloudkms` | Cloud KMS | `EncryptionKey` | high | yes |
| `gcp:cloudscheduler` | Cloud Scheduler | `Scheduler` | high | yes |
| `gcp:cloudtasks` | Cloud Tasks | `Queue` | medium | yes |
| `gcp:composer` | Cloud Composer (Airflow) | `Workflow` | high | yes |
| `gcp:compute` | VPC / Subnets / Routes | `BlockStorage`, `Firewall`, `LoadBalancer`, `Subnet`, `VirtualMachine`, `VirtualNetwork` | high | yes |
| `gcp:container` | GKE | `KubernetesCluster` | high | yes |
| `gcp:dataflow` | Dataflow | `AnalyticsService` | high | yes |
| `gcp:dataproc` | Dataproc | `AnalyticsService` | high | yes |
| `gcp:datastream` | Datastream / Data Fusion | `Workflow` | medium | yes |
| `gcp:deploymentmanager` | Deployment Manager | `AutomationService` | high | yes |
| `gcp:dns` | Cloud DNS | `DNS` | medium | yes |
| `gcp:eventarc` | Eventarc | `EventRule` | medium | yes |
| `gcp:file` | Filestore | `FileStorage` | low | yes |
| `gcp:firestore` | Firestore / Datastore | `NoSQLDatabase` | high | yes |
| `gcp:iam` | Workload Identity Federation | `AccessKey`, `FederatedIdentity`, `Role`, `ServiceAccount` | high | yes |
| `gcp:iam-deny` | IAM Deny Policies | `ConditionalPolicy` | medium | no |
| `gcp:iap` | Identity-Aware Proxy | `PrivateEndpoint` | high | yes |
| `gcp:logging` | Cloud Logging / Audit Logs | `LoggingService` | high | yes |
| `gcp:monitoring` | Cloud Monitoring | `LoggingService` | low | yes |
| `gcp:networkconnectivity` | Network Connectivity Center | `TransitGateway` | medium | yes |
| `gcp:orgpolicy` | Organization Policy | `OrganizationPolicy` | medium | yes |
| `gcp:psc` | Private Service Connect | `PrivateEndpoint` | high | no |
| `gcp:pubsub` | Pub/Sub | `Topic` | medium | yes |
| `gcp:redis` | Memorystore | `Cache` | low | yes |
| `gcp:resourcemanager` | Resource Manager | `Folder`, `Organization`, `Project` | high | yes |
| `gcp:run` | Cloud Run | `ContainerService` | high | yes |
| `gcp:secretmanager` | Secret Manager | `Secret` | high | yes |
| `gcp:securitycenter` | Security Command Center | `SecurityService` | high | yes |
| `gcp:sourcerepos` | Cloud Source Repositories | `ArtifactRepository` | medium | no |
| `gcp:spanner` | Cloud Spanner | `RelationalDatabase` | medium | yes |
| `gcp:sqladmin` | Cloud SQL | `RelationalDatabase` | high | yes |
| `gcp:storage` | Cloud Storage | `ObjectStorage` | high | yes |
| `gcp:workflows` | Workflows | `Workflow` | high | yes |

### 4.3 Azure (60 services)

| Service | Name | Generic types | Relevance | Collected |
|---|---|---|---|---|
| `azure:aci` | Container Instances | `ContainerService` | high | yes |
| `azure:aks` | AKS | `KubernetesCluster` | high | yes |
| `azure:apim` | apim | `APIGateway` | inventory | yes |
| `azure:app` | Container Apps | `ContainerService` | high | yes |
| `azure:appconfig` | App Configuration | `Secret` | medium | yes |
| `azure:arm-deployments` | ARM/Bicep Deployments | `AutomationService` | high | no |
| `azure:automation` | Azure Automation | `AutomationService` | high | yes |
| `azure:b2c` | Azure AD B2C | `FederatedIdentity` | medium | no |
| `azure:batch` | Azure Batch | `BatchJob` | medium | yes |
| `azure:blueprints` | Blueprints/Deployment Stacks | `AutomationService` | medium | no |
| `azure:cache` | Cache for Redis | `Cache` | medium | yes |
| `azure:cdn` | cdn | `LoadBalancer` | inventory | yes |
| `azure:cognitiveservices` | Azure OpenAI / AI Services | `AnalyticsService` | low | yes |
| `azure:compute` | VM Scale Sets | `BlockStorage`, `Snapshot`, `VirtualMachine` | high | yes |
| `azure:containerregistry` | Container Registry | `ContainerRegistry` | high | yes |
| `azure:databricks` | Azure Databricks | `AnalyticsService` | high | yes |
| `azure:datafactory` | Data Factory | `AutomationService` | high | yes |
| `azure:datalake` | Data Lake Storage Gen2 | `DataLake` | high | yes |
| `azure:defender` | Defender for Cloud | `SecurityService` | high | no |
| `azure:devops` | Azure DevOps | `BuildWorker`, `ArtifactRepository` | high | no |
| `azure:dns` | Azure DNS / Private DNS | `DNS` | medium | no |
| `azure:documentdb` | Cosmos DB | `NoSQLDatabase` | high | yes |
| `azure:entra` | Entra ID | `ApplicationIdentity`, `Group`, `HumanIdentity` | high | yes |
| `azure:eventgrid` | Event Grid | `Topic` | medium | yes |
| `azure:eventhub` | Event Hubs | `EventBus` | low | yes |
| `azure:frontdoor` | Front Door / CDN | `PublicEndpoint` | medium | no |
| `azure:hdinsight` | hdinsight | `AnalyticsService` | inventory | yes |
| `azure:keyvault` | Managed HSM | `EncryptionKey`, `Secret` | high | yes |
| `azure:kusto` | kusto | `AnalyticsService` | inventory | yes |
| `azure:lighthouse` | Azure Lighthouse | `ExternalIdentity` | high | no |
| `azure:loganalytics` | Log Analytics / Sentinel | `LoggingService`, `SecurityService` | medium | no |
| `azure:logic` | Logic Apps | `Workflow` | high | yes |
| `azure:managedidentity` | Managed Identities | `ManagedIdentity` | high | yes |
| `azure:mariadb` | mariadb | `RelationalDatabase` | inventory | yes |
| `azure:mgmtgroups` | Management Groups | `ManagementGroup` | high | yes |
| `azure:ml` | Azure ML | `AnalyticsService` | high | yes |
| `azure:monitor` | Azure Monitor / Activity Log | `LoggingService` | high | no |
| `azure:msgraph` | Microsoft Graph (app perms) | `ApplicationIdentity` | high | no |
| `azure:mysql` | mysql | `RelationalDatabase` | inventory | yes |
| `azure:netapp` | Azure NetApp Files | `FileStorage` | low | yes |
| `azure:network` | Azure Firewall | `Firewall`, `LoadBalancer`, `NetworkInterface`, `PrivateEndpoint`, `Subnet`, `VirtualNetwork` | high | yes |
| `azure:notificationhubs` | Notification Hubs | `Topic` | low | yes |
| `azure:policy` | Azure Policy | `ConditionalPolicy`, `OrganizationPolicy` | medium | no |
| `azure:postgresql` | DB for PostgreSQL/MySQL | `RelationalDatabase` | high | yes |
| `azure:privatelink` | Private Link / Endpoints | `PrivateEndpoint` | high | no |
| `azure:purview` | Microsoft Purview | `AnalyticsService` | low | yes |
| `azure:rbac` | Azure RBAC (Authorization) | `Role`, `IAMPolicy`, `ConditionalPolicy` | high | no |
| `azure:recoveryservices` | recoveryservices | `Backup` | inventory | yes |
| `azure:search` | AI Search | `SearchService` | medium | yes |
| `azure:servicebus` | Service Bus | `Queue` | medium | yes |
| `azure:servicefabric` | Service Fabric | `ContainerCluster` | medium | yes |
| `azure:signalr` | signalr | `GenericMessaging` | inventory | yes |
| `azure:sql` | Azure SQL / SQL MI | `RelationalDatabase` | high | yes |
| `azure:storage` | Storage Accounts (Blob/File/Queue/Table) | `ObjectStorage` | high | yes |
| `azure:streamanalytics` | streamanalytics | `AnalyticsService` | inventory | yes |
| `azure:subscription` | subscription | `ResourceGroup`, `Subscription` | medium | yes |
| `azure:subscriptions` | Subscriptions/RG | `Subscription`, `ResourceGroup` | high | no |
| `azure:synapse` | Synapse Analytics | `AnalyticsService` | high | yes |
| `azure:vwan` | Virtual WAN / ER / VPN | `TransitGateway`, `VPN` | medium | no |
| `azure:web` | Azure Functions | `ApplicationPlatform` | high | yes |

---

## 5. Edge taxonomy & derivation rules

Directed capability/relationship edges. Each declares its category, `relationship_kind`, `nature`
(explicit = observed, derived = synthesized, both), the node types it connects, whether it is
**walkable** (attacker-traversable) and **high-value**. The **derivation rule** (`rules/derivation.json`)
gives the conditions and the concrete per-cloud permissions/triggers that realize it.

### 5.1 Categories

| Category | Relationship kinds | Description |
|---|---|---|
| `structural` | `STRUCTURAL` | Inventory/containment. Not attack-traversable by default. |
| `identity_authz` | `AUTHORIZATION` | Membership, roles, permission grants, trust & policy mutation. |
| `execution` | `EXECUTION` | Causing attacker-controlled code to run as some identity. |
| `credential` | `CREDENTIAL` | Reading/creating/using credential & key material. |
| `resource_control` | `CONTROL` | Read/write/admin/ownership over resources. |
| `network` | `NETWORK` | Reachability & exposure. |
| `data` | `STRUCTURAL`, `CREDENTIAL`, `CONTROL` | Data-plane access & exfiltration. |
| `cross_boundary` | `AUTHORIZATION`, `CREDENTIAL`, `CONTROL` | Movement across accounts/projects/subs/tenants/orgs. |
| `derived` | `DERIVED_ATTACK_PATH` | Computed capability summarizing a multi-edge chain. |

### 5.2 Edge states

| State | Meaning |
|---|---|
| `ACTIVE` | All preconditions satisfied now; directly traversable. |
| `CONDITIONAL` | Traversable only if listed conditions hold (e.g. trigger exists, network reachable). |
| `POTENTIAL` | Capability could be created by the source (e.g. can add a trigger) but is not yet realized. |
| `BLOCKED` | An explicit deny / guardrail (SCP, deny assignment, deny policy, boundary) neutralizes it. |
| `UNKNOWN` | Insufficient collection to decide; surfaced for analyst review, excluded from default paths. |

### 5.3 Edge types

#### structural

##### `Contains`
*STRUCTURAL · explicit · non-walkable*

`AdministrativeBoundary`, `ObjectStorage`, `Data`, `Secret`, `ManagementService` → `*`

Container holds child resources/objects: administrative boundaries, storage containers, data stores (SQL servers and their databases/firewall rules), secret vaults (Key Vault and its secrets/keys), management services and their artifacts.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `LocatedIn`
*STRUCTURAL · explicit · non-walkable*

`*` → `AdministrativeBoundary`, `Network`

Placement metadata (region/subnet). Useful for filtering, not traversal.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `AttachedTo`
*STRUCTURAL · explicit · non-walkable*

`NetworkInterface`, `BlockStorage`, `ManagedIdentity`, `IAMPolicy` → `Compute`, `VirtualNetwork`, `Identity`

Physical/logical attachment. Semantic edges (ExecutesAs, HasPolicy) carry the security meaning.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### identity_authz

##### `MemberOf`
*AUTHORIZATION · explicit · walkable (w=1) · **high-value***

`Identity` → `Group`, `Role`

Source inherits the target's permissions via membership.

**Derivation rule** — nature `explicit`

- **AWS:** iam group membership; SSO group assignment
- **GCP:** Google group membership
- **Azure:** Entra group membership (incl. dynamic)

##### `HasRole`
*AUTHORIZATION · explicit · walkable (w=1)*

`Identity` → `Role`

Principal is directly granted a role (Entra role, GCP role binding, IAM role attachment).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `HasPolicy`
*AUTHORIZATION · explicit · non-walkable*

`Identity`, `*` → `Policy`

A policy artifact is attached to a principal/resource. Feeds the permission evaluator; not walked directly.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `HasPermission`
*AUTHORIZATION · both · walkable (w=1)*

`Identity` → `*`

EFFECTIVE permission (post evaluation) of an action on a target. Produced by the permission engine / effective-permission evaluator.

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CanAssume`
*AUTHORIZATION · both · walkable (w=1) · **high-value***

`Identity` → `Role`, `MachineIdentity`, `ServiceAccount`

Source can obtain the target identity's credentials/session (role assumption).

**Derivation rule** — nature `both`; conditions: `trust_relationship`, `iam_permission`, `condition_expression`, `scp_or_org_policy`

- **AWS:** `sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity`, `sts:AssumeRoleWithSAML` — Requires role trust policy to allow source.
- **GCP:** `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.getOpenIdToken`, `iam.serviceAccounts.signJwt` — Short-lived credential minting = de facto assume.
- **Azure:** No direct STS analog; approximate via MI assignment / SP credential add. Prefer CanCreateCredentialFor. Do not equate to AWS AssumeRole.

##### `CanImpersonate`
*AUTHORIZATION · both · walkable (w=1) · **high-value***

`Identity` → `ServiceAccount`, `MachineIdentity`, `ManagedIdentity`, `WorkloadIdentity`, `ApplicationIdentity`

Source acts as target without holding long-lived creds (GCP SA impersonation, act-on-behalf-of).

**Derivation rule** — nature `both`

- **AWS:** Rare; usually expressed as CanAssume.
- **GCP:** `iam.serviceAccounts.getAccessToken`, `iam.serviceAccounts.implicitDelegation`
- **Azure:** App-only token acquisition where app has app-role/consent.

##### `CanFederateAs`
*AUTHORIZATION · both · walkable (w=1) · **high-value***

`Identity`, `FederatedIdentity`, `WorkloadIdentity` → `Role`, `ServiceAccount`, `MachineIdentity`

External/workload identity is trusted to federate into a CSP identity (OIDC/SAML/Workload Identity).

**Derivation rule** — nature `both`; conditions: `trust_relationship`, `condition_expression`

- **AWS:** OIDC/SAML IdP + role trust (e.g. GitHub Actions, IRSA)
- **GCP:** Workload Identity Federation pool + SA binding
- **Azure:** Federated credentials on app registration / MI

##### `CanDelegate`
*AUTHORIZATION · both · walkable (w=2)*

`Identity`, `ApplicationIdentity` → `Identity`

Domain-wide/OAuth delegation to act for other principals.

**Derivation rule** — nature `both`

- **GCP:** Domain-wide delegation on SA
- **Azure:** Delegated Graph permissions / OBO flow

##### `CanPassIdentity`
*AUTHORIZATION · explicit · walkable (w=1) · **high-value***

`Identity` → `Role`, `ServiceAccount`, `ManagedIdentity`, `MachineIdentity`, `VirtualMachine`

Source may attach/pass the target identity to a NEW or existing workload (prereq for CanExecuteAs).

**Derivation rule** — nature `explicit`; conditions: `iam_permission`, `condition_expression`, `role_compatibility`

- **AWS:** `iam:PassRole` — Scoped by resource + often service condition.
- **GCP:** `iam.serviceAccounts.actAs`
- **Azure:** Assigning a user-assigned MI / setting SP on a resource; requires Microsoft.ManagedIdentity/.../assign + write on target.

##### `CanModifyTrust`
*AUTHORIZATION · explicit · walkable (w=1) · **high-value***

`Identity` → `Role`, `TrustPolicy`, `ServiceAccount`, `MachineIdentity`

Source can rewrite who may assume/impersonate the target — self-grant assumption.

**Derivation rule** — nature `explicit`

- **AWS:** `iam:UpdateAssumeRolePolicy`
- **GCP:** `iam.serviceAccounts.setIamPolicy`
- **Azure:** `update federated credentials / SP owner`

##### `CanModifyPolicy`
*AUTHORIZATION · both · walkable (w=1) · **high-value***

`Identity` → `Policy`, `Identity`, `*`

Source can alter an identity/resource policy to grant itself/others more access. Produced both by explicit normalization (IAM/RBAC setPolicy grants) and by derived rules (deny-policy/org-policy modify capabilities that unlock gated edges).

**Derivation rule** — nature `both`

- **AWS:** `iam:PutUserPolicy`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`
- **GCP:** `*.setIamPolicy (e.g. resourcemanager.projects.setIamPolicy)`
- **Azure:** `Microsoft.Authorization/roleAssignments/write`

##### `CanGrantPermission`
*AUTHORIZATION · both · walkable (w=1) · **high-value***

`Identity` → `Identity`, `Project`, `ResourceGroup`, `Subscription`

Source can assign a role/permission to a principal (incl. itself) — privilege escalation primitive.

**Derivation rule** — nature `both`

- **AWS:** `iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:AddUserToGroup`
- **GCP:** `setIamPolicy at project/folder/org`
- **Azure:** `Microsoft.Authorization/roleAssignments/write`, `Owner/User Access Administrator role`

##### `CanAddMember`
*AUTHORIZATION · explicit · walkable (w=1) · **high-value***

`Identity` → `Group`, `Role`, `ServiceIdentity`

Source can add a principal (itself) to a group/role and inherit its permissions.

**Derivation rule** — nature `explicit`

- **AWS:** `iam:AddUserToGroup`
- **GCP:** Workspace group membership admin.
- **Azure:** `group member write (Graph / owner)`

##### `CanRemoveMember`
*AUTHORIZATION · explicit · non-walkable*

`Identity` → `Group`, `Role`

Membership removal — mostly destructive/persistence, not escalation; not walked by default.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### execution

##### `ExecutesAs`
*EXECUTION · explicit · walkable (w=0) · **high-value***

`Compute`, `Messaging`, `AnalyticsService`, `DataWarehouse`, `DataLake`, `Data` → `Identity`, `ServiceIdentity`, `MachineIdentity`, `ServiceAccount`, `ManagedIdentity`, `Role`

A workload (Compute or Messaging) runs under the target identity. Zero-cost link (a fact, not an action) enabling CanExecuteAs derivations. Includes orchestration workflows, logic apps, and event consumers running as a specified identity.

**Derivation rule** — nature `explicit`

- **AWS:** Lambda execution role; EC2 instance profile; ECS task role; Step Functions execution role
- **GCP:** SA attached to GCE/GCF/Cloud Run; Workflow runtime SA (workflows.serviceAccount)
- **Azure:** Managed identity on VM/Function/Container; Logic App identity

##### `CanExecuteAs`
*EXECUTION · derived · walkable (w=1) · **high-value***

`Identity` → `Identity`

Attacker-controlled code can run with the target identity's privileges. Canonical derived escalation edge.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanModifyCode`
*EXECUTION · both · walkable (w=1) · **high-value***

`Identity` → `Compute`, `ContainerRegistry`, `ArtifactRepository`, `KubernetesWorkload`, `Messaging`, `AnalyticsService`, `AutomationService`

Source can change the executable content a compute resource runs, including orchestration workflows and logic apps that are executable definitions. Produced by explicit normalization (code-update permissions) and by derived rules (supply-chain code-injection paths).

**Derivation rule** — nature `both`

- **AWS:** `lambda:UpdateFunctionCode`, `ecr:PutImage`
- **GCP:** `cloudfunctions.functions.update`, `run.services.update`, `artifactregistry.repositories.uploadArtifacts`, `workflows.workflows.update`
- **Azure:** `Function app deploy / SCM write`, `AcrPush`

##### `CanModifyConfiguration`
*EXECUTION · both · walkable (w=1) · **high-value***

`Identity` → `Compute`, `Messaging`, `Network`, `*`

Source can change config (env vars, layers, startup command, identity binding) to gain execution or escalate. Produced by explicit normalization (control-plane config-update permissions) and by derived rules (trigger hijacking, notification redirection).

**Derivation rule** — nature `both`

- **AWS:** `lambda:UpdateFunctionConfiguration`, `ecs:RegisterTaskDefinition`
- **GCP:** `cloudfunctions.functions.update`, `compute.instances.setMetadata`
- **Azure:** `site config write`, `VM extension write`

##### `CanDeploy`
*EXECUTION · explicit · walkable (w=1)*

`Identity` → `Compute`, `ContainerService`, `KubernetesCluster`, `ApplicationPlatform`

Source can deploy new workloads to a platform (then attach identity).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanCreateWorkloadAs`
*EXECUTION · derived · walkable (w=1) · **high-value***

`Identity` → `Identity`

Source can create a new compute resource bound to target identity (create + pass identity).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanAttachIdentity`
*EXECUTION · both · walkable (w=1)*

`Identity` → `Compute`, `Messaging`, `AnalyticsService`, `RelationalDatabase`, `LoadBalancer`, `Data`

Source can attach/replace the identity a compute resource runs as, including updating a workflow/orchestration service's execution identity. Also applies to data resources (caches, databases) where an identity is used for encryption or service-to-service auth. Produced both by explicit normalization (attach/assign permissions on target resources) and by derived rules (e.g., CanPassIdentity + CanModifyConfiguration on target).

**Derivation rule** — nature `both`

- **AWS:** `iam:PassRole + ec2:AssociateIamInstanceProfile`, `ecs:RegisterTaskDefinition`
- **GCP:** `compute.instances.setServiceAccount + actAs`, `workflows.workflows.update + iam.serviceAccounts.actAs`
- **Azure:** `assign user-assigned MI to resource`

##### `CanExecuteCommand`
*EXECUTION · explicit · walkable (w=1) · **high-value***

`Identity` → `VirtualMachine`, `Container`, `ContainerService`, `KubernetesWorkload`, `RemoteManagementService`, `AnalyticsService`, `Notebook`, `ApplicationPlatform`, `AutomationService`

Source can run OS-level commands on a host/container/managed runtime (agent, run-command, exec, session-pool exec). Notebook targets cover managed notebook instances (Vertex AI Workbench, SageMaker) whose kernels execute arbitrary code as the instance's runtime identity.

**Derivation rule** — nature `explicit`

- **AWS:** `ssm:SendCommand`, `ssm:StartSession`, `ec2-instance-connect:SendSSHPublicKey`
- **GCP:** `compute.instances.setMetadata (SSH keys)`, `OS Login roles`
- **Azure:** `Microsoft.Compute/virtualMachines/runCommand/action`, `VM run-command / RunPowerShellScript extension`

##### `CanExecuteOn`
*EXECUTION · derived · walkable (w=1)*

`Identity` → `Compute`

Generalized 'can get code running on this resource' (superset of command/deploy/modify).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanTrigger`
*EXECUTION · explicit · walkable (w=1)*

`Identity`, `Messaging`, `Storage`, `Network`, `AnalyticsService` → `Compute`, `Messaging`, `AnalyticsService`

Source can cause the target to execute (event source, schedule). Includes triggering compute workloads and orchestration workflows. AnalyticsService sources cover analytics engines that invoke compute as part of query execution (e.g. an Athena federated query invoking its Lambda data-source connector).

**Derivation rule** — nature `explicit`

- **AWS:** S3 event; EventBridge rule; SQS/SNS trigger; Step Functions trigger via EventBridge
- **GCP:** Eventarc trigger to Workflow; Cloud Scheduler job to Workflow
- **Azure:** Service Bus trigger; Event Grid trigger to Logic App

##### `CanInvoke`
*EXECUTION · explicit · walkable (w=1)*

`Identity`, `Messaging` → `ServerlessFunction`, `API`, `APIGateway`, `Workflow`, `ContainerService`

Source can directly invoke the target (completes an ExecutesAs escalation when code already attacker-controlled or config changed). Messaging sources include service-to-service invocations (API Gateway invoking Lambda, EventBridge invoking Lambda, etc.).

**Derivation rule** — nature `explicit`

- **AWS:** `lambda:InvokeFunction`
- **GCP:** `cloudfunctions.functions.invoke`, `run.routes.invoke`
- **Azure:** `function key / invoke`

##### `CanStart`
*EXECUTION · explicit · walkable (w=2)*

`Identity` → `Compute`

Source can start a stopped resource (needed to realize CONDITIONAL execution edges).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanSchedule`
*EXECUTION · explicit · walkable (w=2)*

`Identity` → `Scheduler`, `EventRule`, `Workflow`, `AnalyticsService`

Source can create a schedule/trigger to drive execution (persistence + trigger creation).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### credential

##### `CanCreateCredentialFor`
*CREDENTIAL · explicit · walkable (w=1) · **high-value***

`Identity` → `Identity`, `ApplicationIdentity`, `ServiceAccount`, `MachineIdentity`

Source can mint a NEW long-lived/short-lived credential for the target and thus authenticate as it.

**Derivation rule** — nature `explicit`

- **AWS:** `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`
- **GCP:** `iam.serviceAccountKeys.create`
- **Azure:** `add password/cert to app or SP (Application.ReadWrite / MS Graph)`

##### `CanResetCredential`
*CREDENTIAL · explicit · walkable (w=2)*

`Identity` → `Identity`, `HumanIdentity`

Source can reset/replace target's password/MFA and take over.

**Derivation rule** — nature `explicit`

- **AWS:** `iam:UpdateLoginProfile`
- **GCP:** Workspace admin password reset.
- **Azure:** `Authentication Administrator / reset password (Graph)`

##### `CanReadSecret`
*CREDENTIAL · both · walkable (w=1) · **high-value***

`Identity`, `Compute` → `Secret`, `ConnectionString`, `Password`, `APIKey`, `Certificate`, `ApplicationPlatform`

Source can read secret material (often yields creds for another identity/service).

**Derivation rule** — nature `both`; conditions: `iam_permission`, `resource_policy`, `key_permission`

- **AWS:** `secretsmanager:GetSecretValue`, `ssm:GetParameter (SecureString)`
- **GCP:** `secretmanager.versions.access`
- **Azure:** `Key Vault secret get (data-plane / RBAC)`

##### `CanReadCredential`
*CREDENTIAL · both · walkable (w=1)*

`Identity`, `Compute` → `Credential`, `AccessKey`, `Token`, `SSHKey`

Source can obtain a usable credential (instance metadata token, env var, key file).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CanDecrypt`
*CREDENTIAL · explicit · walkable (w=1) · **high-value***

`Identity`, `Compute` → `EncryptionKey`

Source can use a key to decrypt data/secrets (gates CanReadData on encrypted stores).

**Derivation rule** — nature `explicit`

- **AWS:** `kms:Decrypt`
- **GCP:** `cloudkms.cryptoKeyVersions.useToDecrypt`
- **Azure:** `Key Vault key decrypt/unwrapKey`

##### `CanExportKey`
*CREDENTIAL · explicit · walkable (w=1)*

`Identity` → `EncryptionKey`, `SigningKey`, `Certificate`

Source can export raw key material (rare; high impact — persistent offline decrypt/sign).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanCreateKey`
*CREDENTIAL · explicit · walkable (w=2)*

`Identity` → `EncryptionKey`, `ServiceAccount`

Source can create keys (SA key creation overlaps CanCreateCredentialFor).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanSignAs`
*CREDENTIAL · explicit · walkable (w=1) · **high-value***

`Identity` → `SigningKey`, `ServiceAccount`, `ApplicationIdentity`, `EncryptionKey`

Source can sign tokens/blobs as the target (JWT/SAML signing -> forge identity).

**Derivation rule** — nature `explicit`

- **GCP:** `iam.serviceAccounts.signBlob`, `iam.serviceAccounts.signJwt`

##### `CanRetrieveToken`
*CREDENTIAL · both · walkable (w=1)*

`Identity`, `Compute`, `WorkloadIdentity` → `Token`, `Identity`

Source can obtain an access/OIDC token for an identity (metadata endpoint, token mint).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `ExposesCredential`
*CREDENTIAL · derived · walkable (w=1)*

`Compute`, `Storage`, `Data`, `Messaging`, `Secret`, `Cache` → `Credential`, `Identity`, `Secret`

Resource contains/leaks a credential usable for the target identity (env var, code, connstring, metadata, API key). Target can be a Credential, Identity, or Secret/APIKey node.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CredentialsFor`
*CREDENTIAL · explicit · walkable (w=0) · **high-value***

`Secret`, `Credential`, `AccessKey`, `Token`, `Certificate` → `Identity`, `Data`, `ServiceIdentity`

This secret/credential authenticates as the target. Zero-cost link completing credential chains.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### resource_control

##### `CanRead`
*CONTROL · both · walkable (w=2)*

`Identity` → `*`

Read configuration/metadata of a resource (recon; low base value). Produced by explicit normalization (configuration-read IAM permissions) and by derived rules (recon primitives like reading Macie findings to identify sensitive-data targets).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CanWrite`
*CONTROL · both · walkable (w=1)*

`Identity` → `*`

Modify a resource's configuration. Produced by explicit normalization (write permissions) and derived rules (config-write attack paths).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CanDelete`
*CONTROL · both · non-walkable*

`Identity` → `*`

Destructive; persistence/impact not escalation. Excluded from default paths. Produced by explicit normalization (delete-permission IAM actions) and by derived rules (evasion/cover-tracks primitives like disabling detective services).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CanModify`
*CONTROL · both · walkable (w=1)*

`Identity` → `*`

General modify capability (specialized by CanModifyCode/Configuration/Policy where meaningful). Produced by explicit normalization (modify permissions) and derived rules (config-modification attack paths like CloudTrail tampering, logging-service disablement).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CanAdminister`
*CONTROL · explicit · walkable (w=1) · **high-value***

`Identity` → `*`

Full control (admin/owner) over a resource — implies most other capabilities on it.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanTakeOwnership`
*CONTROL · explicit · walkable (w=1)*

`Identity` → `*`, `ApplicationIdentity`

Source can become owner (Azure SP/app owner, resource owner) and thereby self-grant control.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanControl`
*CONTROL · derived · walkable (w=0) · **high-value***

`Identity` → `*`

Derived summary: source effectively controls target (admin OR sufficient sub-capabilities).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanCreate`
*CONTROL · explicit · walkable (w=2)*

`Identity` → `AdministrativeBoundary`, `*`

Source can create new resources of a type within a scope.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CanReplace`
*CONTROL · explicit · walkable (w=1)*

`Identity` → `*`

Delete+recreate to inherit name/identity/trust (config-drift escalation).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### network

##### `CanNetworkReach`
*NETWORK · derived · walkable (w=1)*

`Compute`, `Network`, `Identity`, `Messaging` → `Compute`, `Data`, `Network`, `PrivateEndpoint`, `Storage`, `Messaging`

Source can reach target over the network (post SG/firewall/route evaluation). Messaging source/target covers publicly- or privately-reachable messaging endpoints (a queue/topic/event-bus with a public resource policy is an internet-reachable target; a private messaging endpoint is a private-link source/target) — consistent with ExposedToInternet and PrivateReachability, which already admit the Messaging class.

**Derivation rule** — nature `derived`; conditions: `network_reachability`; realized directly (no per-cloud specialization)

##### `CanReachPort`
*NETWORK · derived · walkable (w=1)*

`Compute`, `Network` → `Compute`, `Data`, `Network`

Reachability to a specific service port (gates exploitation of a listening service).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `RoutesTo`
*NETWORK · explicit · non-walkable*

`Route`, `Subnet`, `TransitGateway` → `Network`, `Subnet`

Routing fact feeding CanNetworkReach derivation.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `PeeredWith`
*NETWORK · explicit · non-walkable*

`VirtualNetwork` → `VirtualNetwork`

Network peering — expands reachability across VPCs/VNets/accounts.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `ExposedToInternet`
*NETWORK · derived · walkable (w=1) · **high-value***

`Compute`, `Data`, `PublicEndpoint`, `LoadBalancer`, `Storage`, `Messaging`, `DNS` → `AnonymousIdentity`

Target is reachable/abusable from the public internet — common attack entry point (incl. a queue/topic/API with a public/wildcard resource policy).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `ExposedToTenant`
*NETWORK · derived · walkable (w=2)*

`*` → `Tenant`, `Organization`

Reachable/usable by any principal in the tenant/org (broad blast radius).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `ExposedToAccount`
*NETWORK · derived · walkable (w=2)*

`*` → `Account`, `Subscription`, `Project`

Reachable/usable account/subscription/project-wide.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `PrivateReachability`
*NETWORK · derived · walkable (w=1)*

`Compute`, `Messaging`, `Network` → `Data`, `PrivateEndpoint`, `Compute`, `Storage`

Reachable only via private networking (PrivateLink/PE/PSC) — needs a foothold in-network. Includes private APIs and messaging endpoints accessible only via interface endpoints, and object storage reached via a private/gateway endpoint (Azure Blob/Files PE, GCS via PSC). Network sources cover the endpoint/distribution itself acting as the reachability actor (e.g. a CloudFront distribution's OAC/OAI reaching a private S3 origin, or a Private Endpoint node).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

#### data

##### `CanReadData`
*CONTROL · derived · walkable (w=1) · **high-value***

`Identity`, `Compute` → `Storage`, `Data`, `Messaging`, `ApplicationPlatform`

Effective data-plane read (control-plane perm + network reach + decrypt if encrypted). Includes reading messages from a queue/topic/stream.

**Derivation rule** — nature `derived`; conditions: `iam_permission`, `resource_policy`, `network_reachability`, `key_permission`; realized directly (no per-cloud specialization)

##### `CanWriteData`
*CONTROL · derived · walkable (w=1)*

`Identity`, `Compute` → `Storage`, `Data`, `Messaging`

Effective data-plane write (can poison code/artifacts/config → onward execution). Includes publishing/sending to a queue/topic/event bus.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanDeleteData`
*CONTROL · derived · non-walkable*

`Identity`, `Compute` → `Storage`, `Data`

Destructive impact; not escalation.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanExfiltrate`
*CONTROL · derived · walkable (w=1)*

`Identity`, `Compute` → `Storage`, `Data`, `Snapshot`

Can move data out of boundary (share snapshot cross-account, presign URL, replicate).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `ContainsSecret`
*CREDENTIAL · explicit · walkable (w=1)*

`Storage`, `Data`, `Compute`, `Messaging` → `Secret`, `Credential`

Resource stores secret material (drives ExposesCredential).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `ContainsCredential`
*CREDENTIAL · explicit · walkable (w=1)*

`Storage`, `Data`, `Compute`, `Messaging` → `Credential`, `AccessKey`, `Token`

Resource stores a usable credential. Includes hardcoded credentials in workflow definitions, SAS keys in message connectors, and API keys in event subscriptions.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `ContainsResourceReference`
*STRUCTURAL · explicit · non-walkable*

`Data`, `Storage`, `Compute`, `Network` → `*`

Recon: resource references another (connection targets, IaC). Aids collection, not traversal. Network sources (e.g., Route 53 DNS zones) reference alias targets like ELB/CloudFront/S3; dangling aliases are a legitimate structural relationship.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### cross_boundary

##### `CanEnterAccount`
*CONTROL · derived · walkable (w=1) · **high-value***

`Identity` → `Account`

Source can obtain a principal/session inside the target AWS account.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanEnterSubscription`
*CONTROL · derived · walkable (w=1) · **high-value***

`Identity` → `Subscription`

Source can gain control-plane access within the target subscription.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanEnterProject`
*CONTROL · derived · walkable (w=1) · **high-value***

`Identity` → `Project`

Source can gain access within the target GCP project.

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanEnterTenant`
*CONTROL · derived · walkable (w=1) · **high-value***

`Identity` → `Tenant`

Source can obtain a principal in the target Entra tenant (guest, multi-tenant app, B2B).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanEnterOrganization`
*CONTROL · derived · walkable (w=1) · **high-value***

`Identity` → `Organization`

Source reaches org-level control (management account, org policy admin).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CrossAccountTrust`
*AUTHORIZATION · both · walkable (w=1)*

`Account`, `Role`, `ResourcePolicy`, `Data`, `Snapshot`, `DataLake`, `Storage` → `Account`, `ExternalIdentity`, `Subscription`, `AnonymousIdentity`

A trust/resource policy names a principal in another account (feeds CanAssume/CanEnterAccount). Produced by explicit normalization (policy artifact parsing) and by derived rules (cross-account data-resource sharing patterns like S3 bucket policy with foreign principal). Subscription targets cover Azure's account-boundary analog — a cross-subscription trust (e.g. an approved cross-subscription Private Endpoint connection, or cross-subscription VNet peering).

**Derivation rule** — nature `both`; realized directly (no per-cloud specialization)

##### `CrossTenantTrust`
*AUTHORIZATION · explicit · walkable (w=1)*

`Tenant`, `ApplicationIdentity` → `Tenant`, `ExternalIdentity`

B2B/guest/multi-tenant app trust across Entra tenants.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CrossProjectTrust`
*AUTHORIZATION · explicit · walkable (w=1)*

`Project`, `ServiceAccount`, `ResourcePolicy`, `Snapshot` → `Project`, `ExternalIdentity`, `ServiceAccount`

Cross-project IAM binding / SA usage. ServiceAccount targets cover a workload in one project running as (trusting) a service account owned by another project (e.g. a Vertex AI job or Workbench instance with a cross-project runtime SA) — symmetric with ServiceAccount as a source.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `FederatesTo`
*AUTHORIZATION · explicit · walkable (w=1) · **high-value***

`Identity`, `ApplicationIdentity`, `WorkloadIdentity` → `Identity`, `Role`, `ServiceAccount`

Identity in provider A is trusted to obtain an identity in provider B (OIDC/SAML/WIF). Enables cross-cloud paths.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `CredentialValidFor`
*CREDENTIAL · explicit · walkable (w=1)*

`Secret`, `Credential`, `Token` → `Identity`, `ServiceIdentity`

A credential harvested in one environment authenticates to another (cross-cloud/SaaS).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `AuthenticatesTo`
*AUTHORIZATION · explicit · walkable (w=1)*

`Identity`, `Credential` → `*`, `Data`, `API`

Credential/identity authenticates to a service/endpoint (incl. SaaS/DB).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `TrustsExternalIdentity`
*AUTHORIZATION · explicit · walkable (w=1)*

`Role`, `ServiceAccount`, `ApplicationIdentity`, `ManagedIdentity`, `ResourcePolicy`, `TrustPolicy`, `GenericPolicy` → `ExternalIdentity`, `FederatedIdentity`, `WorkloadIdentity`

Target trusts an external/federated/workload principal — inbound cross-boundary access (incl. k8s IRSA/WI federation). Source can be an identity (principal), a resource policy, or a policy document (e.g., B2C trust policy) that declares the trust.

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

##### `ExternalIdentityMapsTo`
*AUTHORIZATION · explicit · walkable (w=1)*

`ExternalIdentity`, `FederatedIdentity`, `WorkloadIdentity` → `Identity`, `Role`, `ServiceAccount`

An external/workload identity resolves to a concrete internal principal (guest->member, IdP subject->role, k8s SA->IAM role).

**Derivation rule** — nature `explicit`; realized directly (no per-cloud specialization)

#### derived

##### `Controls`
*DERIVED_ATTACK_PATH · derived · walkable (w=0) · **high-value***

`Identity` → `AdministrativeBoundary`, `*`

Terminal control edge: source can administer the target boundary/resource (objective attainment).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

##### `CanEscalateTo`
*DERIVED_ATTACK_PATH · derived · walkable (w=0) · **high-value***

`Identity` → `Identity`

Derived: source can become an identity with strictly greater privilege (rolls up an escalation chain).

**Derivation rule** — nature `derived`; realized directly (no per-cloud specialization)

---

## 6. Exposure DB

Every place a customer-controlled **credential/secret can leak**, mapped to the RAGE edge it
emits, its collection recipe, where it sits, and what leaks. `exposure-db/*.json` are the
registries; `exposure-db/vocabulary.json` is the controlled vocabulary.

**1049 exposure sites** across 204 service catalogs — 91 AWS services / 406 sites, 54 GCP services / 265 sites, 59 Azure services / 378 sites.

| Emits (RAGE edge) | Sites |
|---|---|
| `ContainsSecret` | 560 |
| `ContainsCredential` | 214 |
| `ExposesCredential` | 122 |
| `CanReadData` | 117 |
| `CanReadCredential` | 22 |
| `CanReadSecret` | 14 |

**By severity:** critical 564 · high 233 · medium 250 · low 2

**Top data kinds:** `credential` (962), `sensitive_data` (618), `api_key` (591), `password` (495), `pii` (370), `connection_string` (321), `access_key` (308), `secret_key` (306), `oauth_token` (262), `customer_data` (173), `source_code_secret` (118), `private_key` (106)

**Vocabulary** — `location_kind` (20), `data_kinds` (20), `access_mode` (`read_api`, `data_plane`, `creation_response_only`, `write_only_input`, `indirect_destination`).

---

*10 classes · 105 node types · 80 edges · 80 derivation rules · 106+53+60 resource types · 1049 exposure sites. Generated from RAGE registries by `tools/gen_taxonomy.py`.*
