FROM hasura/graphql-engine:v2.7.0.cli-migrations-v3

COPY ./hasura/migrations /hasura-migrations
COPY ./hasura/metadata /hasura-metadata

ENV HASURA_GRAPHQL_ENABLE_CONSOLE="false"
ENV HASURA_GRAPHQL_DEV_MODE="false"

EXPOSE 8080