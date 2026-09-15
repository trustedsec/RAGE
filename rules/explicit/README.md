# Explicit (Normalization) Rules

Explicit rules turn **raw collected CSP config** into **explicit edges** that
conform to `schema/edges.yaml`. They are the bridge between a provider adapter's
output and the common graph. Unlike derived rules they do not combine edges;
they translate one observed fact into one (or few) explicit edges with evidence.

Format mirrors the derived-rule format but matches raw records instead of edges:

```yaml
rule:
  id: aws-lambda-executes-as
  emits: ExecutesAs
  applies_to: [aws]
  match_record:
    resource_type: AWS::Lambda::Function
    field: Configuration.Role            # present & non-empty
  emit:
    source: <this function node>
    target: <role node for Configuration.Role>
    api_source: lambda:GetFunctionConfiguration
    evidence_field: Configuration.Role
    narrative: "{function.name} executes as {role.name} (Lambda execution role)."
```

See `aws-lambda.yaml` for a worked example. Provider-specific normalization
lives in `/rules/explicit/<provider>/`.
