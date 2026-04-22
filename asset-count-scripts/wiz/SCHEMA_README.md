# Wiz API GraphQL Schema Files

This directory contains the Wiz API GraphQL schema files fetched using introspection.

## Files

### 1. `wiz_graphql_schema_full.json`
The complete GraphQL schema in JSON format. This includes all types, queries, mutations, and their complete definitions.

**Usage:** Reference this when you need detailed type information or want to understand the complete API structure.

### 2. `wiz_graphql_schema_relevant.json`
Filtered schema containing only types relevant to cloud resources, cloud accounts, subscriptions, assets, images, and containers.

**Usage:** Easier to navigate than the full schema when working with cloud resource-related queries.

### 3. `wiz_graphql_schema_summary.txt`
Human-readable summary of relevant types with their fields and descriptions.

**Usage:** Quick reference guide to see what fields are available on each type.

## Updating the Schema

To refresh the schema (e.g., when Wiz API updates):

```bash
python fetch_wiz_schema.py
```

This will:
1. Authenticate with the Wiz API
2. Fetch the complete schema using GraphQL introspection
3. Generate all three files listed above

## Key Findings

### CloudResource Fields

The `CloudResource` type has these fields available:

```graphql
type CloudResource {
  id: ID!
  name: String!
  type: GraphEntityTypeValue!
  nativeType: String
  subscriptionId: String
  subscriptionName: String
  subscriptionExternalId: String
  graphEntity: GraphEntity
}
```

### CloudAccount Fields

The `CloudAccount` type (accessed via `cloudAccounts` query) has:

```graphql
type CloudAccount {
  id: ID!
  name: String!
  externalId: String!
  cloudProvider: CloudPlatform!
  # ... and many more fields
}
```

## Using the Schema

When writing GraphQL queries for the Wiz API:

1. Check `wiz_graphql_schema_summary.txt` to see available fields
2. Reference the exact field names (case-sensitive)
3. Note which fields are nullable vs non-null (marked with `!`)
4. Consider pagination for list queries using `pageInfo`

## Example Query Structure

```graphql
query CloudResourcesPaginated($filterBy: CloudResourceFilters, $first: Int, $after: String) {
  cloudResources(filterBy: $filterBy, first: $first, after: $after) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      id
      name
      type
      subscriptionId
      subscriptionName
      subscriptionExternalId
    }
  }
}
```

## Notes

- The schema is fetched from: `https://api.us10.app.wiz.io/graphql`
- Authentication is required (same credentials as the main script)
- The schema may vary based on your Wiz tenant and permissions
- Schema introspection is a standard GraphQL feature

