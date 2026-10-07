import { ApolloServer } from "@apollo/server";
import { schema } from "./schema";

export const server = new ApolloServer({ schema, introspection: process.env.NODE_ENV !== "production", csrfPrevention: true });
