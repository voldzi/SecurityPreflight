import { z } from "zod";

export const dataClassificationSchema = z.enum(["public", "internal", "confidential", "sensitive", "health-data"]);

export const projectConfigSchema = z.object({
  projectName: z.string().min(1),
  dataClassification: dataClassificationSchema.default("internal"),
  defaultProfile: z.string().default("fast-local"),
  api: z
    .object({
      openapi: z.string().default("openapi/openapi.json"),
      localBaseUrl: z.string().url().optional(),
      healthEndpoint: z.string().default("/health"),
      readyEndpoint: z.string().default("/ready")
    })
    .optional(),
  scans: z
    .object({
      sast: z.boolean().default(true),
      sca: z.boolean().default(true),
      secrets: z.boolean().default(true),
      containers: z.boolean().default(false),
      iac: z.boolean().default(false),
      dast: z.boolean().default(false),
      sbom: z.boolean().default(false)
    })
    .default({}),
  dast: z
    .object({
      allowActiveScan: z.boolean().default(false),
      allowedHosts: z.array(z.string()).default(["localhost", "127.0.0.1", "host.docker.internal"]),
      excludedPaths: z.array(z.string()).default([]),
      timeoutSeconds: z.number().int().positive().default(900)
    })
    .default({}),
  gate: z
    .object({
      failOnCritical: z.boolean().default(true),
      failOnHigh: z.boolean().default(true),
      failOnMediumForSensitiveData: z.boolean().default(true)
    })
    .default({})
});

export const globalConfigSchema = z.object({
  defaultReportsPath: z.string().default("/reports"),
  toolExecutionMode: z.enum(["docker", "host"]).default("docker"),
  defectDojo: z
    .object({
      enabled: z.boolean().default(false),
      baseUrl: z.string().default(""),
      apiTokenRef: z.string().default("")
    })
    .default({}),
  policies: z
    .object({
      allowProductionActiveDast: z.boolean().default(false),
      requireRiskExceptionExpiry: z.boolean().default(true),
      requireOpenApiJsonForRestApi: z.boolean().default(true)
    })
    .default({})
});

export type ProjectConfig = z.infer<typeof projectConfigSchema>;
export type GlobalConfig = z.infer<typeof globalConfigSchema>;
